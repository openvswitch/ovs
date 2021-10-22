// Copyright 2018 Google LLC
// Copyright 2018-present Open Networking Foundation
// Copyright(c) 2021 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0

#include "yang_parse_tree.h"

#include <list>
#include <string>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/synchronization/mutex.h"
#include "grpcpp/grpcpp.h"
#include "stratum/glue/status/status_macros.h"
#include "gnmi_publisher.h"
#include "yang_parse_tree_paths.h"

namespace stratum {
namespace hal {

TreeNode::TreeNode(const TreeNode& src) {
  name_ = src.name_;
  // Deep-copy children.
  this->CopySubtree(src);
}

void TreeNode::CopySubtree(const TreeNode& src) {
  // Copy the handlers.
  on_timer_handler_ = src.on_timer_handler_;
  on_poll_handler_ = src.on_poll_handler_;
  on_change_handler_ = src.on_change_handler_;
  on_update_handler_ = src.on_update_handler_;
  on_replace_handler_ = src.on_replace_handler_;
  on_delete_handler_ = src.on_delete_handler_;
  // Set the parent.
  parent_ = src.parent_;
  // Copy the supported_* flags.
  supports_on_timer_ = src.supports_on_timer_;
  supports_on_poll_ = src.supports_on_poll_;
  supports_on_change_ = src.supports_on_change_;
  supports_on_update_ = src.supports_on_update_;
  supports_on_replace_ = src.supports_on_replace_;
  supports_on_delete_ = src.supports_on_delete_;
  // Copy flags.
  is_name_a_key_ = src.is_name_a_key_;

  // Deep-copy children.
  for (const auto& entry : src.children_) {
    children_.emplace(entry.first, TreeNode(*this, entry.first));
    children_[entry.first].CopySubtree(entry.second);
  }
}

::util::Status TreeNode::VisitThisNodeAndItsChildren(
    const TreeNodeEventHandlerPtr& handler, const GnmiEvent& event,
    const ::gnmi::Path& path, GnmiSubscribeStream* stream) const {
  RETURN_IF_ERROR((this->*handler)(event, path, stream));
  for (const auto& child : children_) {
    RETURN_IF_ERROR(child.second.VisitThisNodeAndItsChildren(
        handler, event, child.second.GetPath(), stream));
  }
  return ::util::OkStatus();
}

::util::Status TreeNode::RegisterThisNodeAndItsChildren(
    const EventHandlerRecordPtr& record) const {
  RETURN_IF_ERROR(this->on_change_registration_(record));
  for (const auto& child : children_) {
    RETURN_IF_ERROR(child.second.RegisterThisNodeAndItsChildren(record));
  }
  return ::util::OkStatus();
}

::gnmi::Path TreeNode::GetPath() const {
  std::list<const TreeNode*> elements;
  for (const TreeNode* node = this; node != nullptr; node = node->parent_) {
    elements.push_front(node);
  }

  // Remove the first element as it is a fake root and should never apear in the
  // path.
  if (!elements.empty()) elements.pop_front();

  ::gnmi::Path path;
  ::gnmi::PathElem* elem = nullptr;
  for (const auto& element : elements) {
    if (element->is_name_a_key_) {
      if (elem != nullptr) {
        (*elem->mutable_key())["name"] = element->name_;
      } else {
        LOG(ERROR) << "Found a key element without a parent!";
      }
    } else {
      elem = path.add_elem();
      elem->set_name(element->name_);
    }
  }
  return path;
}

const TreeNode* TreeNode::FindNodeOrNull(const ::gnmi::Path& path) const {
  // Map the input path to the supported one - walk the tree of known elements
  // element by element starting from this node and if the element is found the
  // move to the next one. If not found, return an error (nullptr).
  int element = 0;
  const TreeNode* node = this;
  for (; node != nullptr && !node->children_.empty() &&
         element < path.elem_size();) {
    node = gtl::FindOrNull(node->children_, path.elem(element).name());
    auto* search = gtl::FindOrNull(path.elem(element).key(), "name");
    if (search != nullptr && node != nullptr) {
      node = gtl::FindOrNull(node->children_, *search);
    }
    ++element;
  }
  return node;
}

void YangParseTree::SendNotification(const GnmiEventPtr& event) {
  absl::WriterMutexLock r(&root_access_lock_);
  if (!gnmi_event_writer_) return;
  // Pass the event to the gNMI publisher using the gNMI event notification
  // channel.
  // The GnmiEventPtr is a smart pointer (shared_ptr<>) and it takes care of
  // the memory allocated to this event object once the event is handled by
  // the GnmiPublisher.
  if (!gnmi_event_writer_->Write(event)) {
    // Remove WriterInterface if it is no longer operational.
    gnmi_event_writer_.reset();
  }
}

void YangParseTree::ProcessPushedConfig(
    const ConfigHasBeenPushedEvent& change) {
  absl::WriterMutexLock r(&root_access_lock_);

  // Translation from node ID to an object describing the node.
  absl::flat_hash_map<uint64, const Node*> node_id_to_node;
  for (const auto& node : change.new_config_.nodes()) {
    node_id_to_node[node.id()] = &node;
  }

  // An empty config to be used when node ID is not defined.
  const NodeConfigParams empty_node_config;

  // Translation from port ID to node ID.
  absl::flat_hash_map<uint32, uint64> port_id_to_node_id;
  for (const auto& singleton : change.new_config_.singleton_ports()) {
    const NodeConfigParams& node_config =
        node_id_to_node[singleton.node()]
            ? node_id_to_node[singleton.node()]->config_params()
            : empty_node_config;
    AddSubtreeInterfaceFromSingleton(singleton, node_config);
    port_id_to_node_id[singleton.id()] = singleton.node();
  }

  for (const auto& optical : change.new_config_.optical_network_interfaces()) {
    AddSubtreeInterfaceFromOptical(optical);
  }

  for (const auto& trunk : change.new_config_.trunk_ports()) {
    // Find out on which node the trunk is created.
    // TODO(b/70300190): Once TrunkPort message in common.proto is extended to
    // include node_id remove 3 following lines.
    constexpr uint64 kNodeIdUnknown = 0xFFFF;
    uint64 node_id = trunk.members_size() ? port_id_to_node_id[trunk.members(0)]
                                          : kNodeIdUnknown;
    const NodeConfigParams& node_config =
        node_id != kNodeIdUnknown ? node_id_to_node[node_id]->config_params()
                                  : empty_node_config;
    AddSubtreeInterfaceFromTrunk(trunk.name(), node_id, trunk.id(),
                                 node_config);
  }
  // Add all chassis-related gNMI paths.
  AddSubtreeChassis(change.new_config_.chassis());
  // Add all system-related gNMI paths.
  AddSubtreeSystem();
  // Add all node-related gNMI paths.
  for (const auto& node : change.new_config_.nodes()) {
    AddSubtreeNode(node);
  }
}

bool YangParseTree::IsWildcard(const std::string& name) const {
  if (name == "*") return true;
  if (name == "...") return true;
  return false;
}

::util::Status YangParseTree::PerformActionForAllNonWildcardNodes(
    const gnmi::Path& path, const gnmi::Path& subpath,
    const std::function<::util::Status(const TreeNode& leaf)>& action) const {
  const auto* root = root_.FindNodeOrNull(path);
  CHECK_RETURN_IF_FALSE(root);
  ::util::Status ret = ::util::OkStatus();
  for (const auto& entry : root->children_) {
    if (IsWildcard(entry.first)) {
      // Skip this one!
      continue;
    }
    auto* leaf = subpath.elem_size() ? entry.second.FindNodeOrNull(subpath)
                                     : &entry.second;
    if (leaf == nullptr) {
      // This will happen if the subpath does not exist in the path.
      // For example, trying to query node-id from all components
      // but some components do not have node-id leaf.
      continue;
    }
    APPEND_STATUS_IF_ERROR(ret, action(*leaf));
  }
  return ret;
}

YangParseTree::YangParseTree(BfChassisManager *bf_chassis_manager)
     : bf_chassis_manager_(ABSL_DIE_IF_NULL(bf_chassis_manager)) {
  // Add the minimum nodes:
  //   /interfaces/virtual-interface[name=*]/state/ifindex
  //   /interfaces/virtual-interface[name=*]/state/name
  //   /interfaces/virtual-interface/...
  //   /
  // The rest of nodes will be added once the config is pushed.
  absl::WriterMutexLock l(&root_access_lock_);
  AddSubtreeAllInterfaces();
  AddSubtreeAllComponents();
  AddRoot();
}

TreeNode* YangParseTree::AddNode(const ::gnmi::Path& path) {
  // No need to lock the mutex - it is locked by method calling this one.
  TreeNode* node = &root_;
  for (const auto& element : path.elem()) {
    TreeNode* child = gtl::FindOrNull(node->children_, element.name());
    if (child == nullptr) {
      // This path is not supported yet. Let's add a node with default
      // processing.
      node->children_.emplace(element.name(), TreeNode(*node, element.name()));
      child = gtl::FindOrNull(node->children_, element.name());
    }
    node = child;
    auto* search = gtl::FindOrNull(element.key(), "name");
    if (search == nullptr) {
      continue;
    }

    // A filtering pattern has been found!
    child = gtl::FindOrNull(node->children_, *search);
    if (child == nullptr) {
      // This path is not supported yet. Let's add a node with default
      // processing.
      node->children_.emplace(
          *search, TreeNode(*node, *search, true /* mark as a key */));
      child = gtl::FindOrNull(node->children_, *search);
    }
    node = child;
  }
  return node;
}

::util::Status YangParseTree::CopySubtree(const ::gnmi::Path& from,
                                          const ::gnmi::Path& to) {
  // No need to lock the mutex - it is locked by method calling this one.
  // Find the source subtree root.
  const TreeNode* source = root_.FindNodeOrNull(from);
  if (source == nullptr) {
    // This path is not defined!
    return MAKE_ERROR(ERR_INVALID_PARAM) << "Source path does not exist";
  }
  // Now 'source' points to the root of the source subtree.

  // Set 'dest' to the insertion point of the new subtree.
  TreeNode* node = AddNode(to);
  // Now 'node' points to the insertion point of the new subtree.

  // Deep-copy the source subtree.
  node->CopySubtree(*source);

  return ::util::OkStatus();
}

const TreeNode* YangParseTree::FindNodeOrNull(const ::gnmi::Path& path) const {
  absl::WriterMutexLock l(&root_access_lock_);

  // Map the input path to the supported one - walk the tree of known elements
  // element by element starting from the root and if the element is found the
  // move to the next one. If not found, return an error (nullptr).
  return root_.FindNodeOrNull(path);
}

const TreeNode* YangParseTree::GetRoot() const {
  absl::WriterMutexLock l(&root_access_lock_);

  return &root_;
}

void YangParseTree::AddSubtreeInterfaceFromTrunk(
    const std::string& name, uint64 node_id, uint32 port_id,
    const NodeConfigParams& node_config) {
  YangParseTreePaths::AddSubtreeInterfaceFromTrunk(name, node_id, port_id,
                                                   node_config, this);
}

void YangParseTree::AddSubtreeInterfaceFromSingleton(
    const SingletonPort& singleton, const NodeConfigParams& node_config) {
  YangParseTreePaths::AddSubtreeInterfaceFromSingleton(singleton, node_config,
                                                       this);
}

void YangParseTree::AddSubtreeInterfaceFromOptical(
    const OpticalNetworkInterface& optical) {
  YangParseTreePaths::AddSubtreeInterfaceFromOptical(optical, this);
}

void YangParseTree::AddSubtreeNode(const Node& node) {
  YangParseTreePaths::AddSubtreeNode(node, this);
}

void YangParseTree::AddSubtreeChassis(const Chassis& chassis) {
  YangParseTreePaths::AddSubtreeChassis(chassis, this);
}

void YangParseTree::AddSubtreeSystem() {
  YangParseTreePaths::AddSubtreeSystem(this);
}

void YangParseTree::AddSubtreeAllInterfaces() {
  // No need to lock the mutex - it is locked by method calling this one.

  // Add all nodes defined in YangParseTreePaths class.
  YangParseTreePaths::AddSubtreeAllInterfaces(this);
}

// Setup
// * the /components/component[name="*"]/name path to make possible all
//   components' names retrieval.
// * the /components/component/* path to retrieve all the nodes for the
//   specific component.
void YangParseTree::AddSubtreeAllComponents() {
  // No need to lock the mutex - it is locked by method calling this one.
  YangParseTreePaths::AddSubtreeAllComponents(this);
}

void YangParseTree::AddRoot() {
  // No need to lock the mutex - it is locked by method calling this one.

  // Add root element
  YangParseTreePaths::AddRoot(this);
}
}  // namespace hal
}  // namespace stratum
