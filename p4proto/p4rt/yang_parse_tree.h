// Copyright 2018 Google LLC
// Copyright 2018-present Open Networking Foundation
// Copyright(c) 2021 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0

#ifndef STRATUM_HAL_LIB_COMMON_YANG_PARSE_TREE_H_
#define STRATUM_HAL_LIB_COMMON_YANG_PARSE_TREE_H_

#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

#include "absl/synchronization/mutex.h"
#include "gnmi/gnmi.grpc.pb.h"
#include "p4/gnmi/gnmi.grpc.pb.h"
#include "stratum/hal/lib/common/common.pb.h"
#include "stratum/hal/lib/common/gnmi_events.h"
#include "stratum/hal/lib/common/switch_interface.h"
#include "stratum/hal/lib/common/writer_interface.h"
#include "stratum/lib/macros.h"
#include "bfIntf/bf_chassis_manager.h"

namespace stratum {
namespace hal {

class EventHandlerRecord;
class GnmiEvent;
class SubscriptionTestBase;
class YangParseTreePaths;
class YangParseTreeTest;

using TreeNodeEventHandler = std::function<::util::Status(
    const GnmiEvent& event, const ::gnmi::Path& path,
    GnmiSubscribeStream* stream)>;
using TreeNodeSetHandler = std::function<::util::Status(
    const ::gnmi::Path& path, const ::google::protobuf::Message& val,
    CopyOnWriteChassisConfig* config)>;
using TreeNodeDeleteHandler = std::function<::util::Status(
    const ::gnmi::Path& path, CopyOnWriteChassisConfig* config)>;

using EventHandlerRecordPtr = std::weak_ptr<EventHandlerRecord>;
using TreeNodeEventRegistration =
    std::function<::util::Status(const EventHandlerRecordPtr& record)>;

// YANG model is conceptually a tree with each leaf representing a value that is
// interesting from the point of view of the gNMI client. This class implements
// nodes and leafs of that tree.
// When a client requests subscription for a node or a leaf this tree is used to
// check if such node or leaf is supported - it is done by walking the tree
// starting from the root and then checking if the next element in the path can
// be found in the map of children kept by the root TreeNode object. If found,
// this node is used to check if the second element of the path can be found in
// its children and so on until the first unknown path element is found (and the
// client is notified that such leaf is not supported) or the whole path is
// processed (which means that the leaf is supported).
class TreeNode {
 public:
  using SupportsOnPtr = bool TreeNode::*;
  using TargetDefinedModeFunc =
      std::function<::util::Status(::gnmi::Subscription* subscription)>;

  TreeNode()
      : parent_(nullptr),
        name_(""),
        is_name_a_key_(false),
        supports_on_timer_(false),
        supports_on_change_(false),
        supports_on_poll_(false),
        supports_on_update_(false),
        supports_on_replace_(false),
        supports_on_delete_(false) {}
  TreeNode(const TreeNode& parent, const std::string& name,
           bool is_name_a_key = false)
      : parent_(&parent),
        name_(name),
        is_name_a_key_(is_name_a_key),
        supports_on_timer_(false),
        supports_on_change_(false),
        supports_on_poll_(false),
        supports_on_update_(false),
        supports_on_replace_(false),
        supports_on_delete_(false) {}
  TreeNode(const TreeNode& src);

  void CopySubtree(const TreeNode& src);

  // Overrides the default-not-supported handler procedure called when
  // a set-update request is processed with a user-specified one.
  TreeNode* SetOnUpdateHandler(const TreeNodeSetHandler& handler) {
    on_update_handler_ = handler;
    supports_on_update_ = true;
    return this;
  }

  // Overrides the default-not-supported handler procedure called when
  // a set-replace request is processed with a user-specified one.
  TreeNode* SetOnReplaceHandler(const TreeNodeSetHandler& handler) {
    on_replace_handler_ = handler;
    supports_on_replace_ = true;
    return this;
  }

  // Overrides the default-not-supported handler procedure called when
  // a set-delete request is processed with a user-specified one.
  TreeNode* SetOnDeleteHandler(const TreeNodeDeleteHandler& handler) {
    on_delete_handler_ = handler;
    supports_on_delete_ = true;
    return this;
  }

  // Overrides the default-process-whole-sub-tree handler procedure called when
  // a timer event is processed with a user-specified one.
  TreeNode* SetOnTimerHandler(const TreeNodeEventHandler& handler) {
    on_timer_handler_ = handler;
    supports_on_timer_ = true;
    return this;
  }

  // Overrides the default-process-whole-sub-tree handler procedure called when
  // a poll event is processed with a user-specified one.
  TreeNode* SetOnPollHandler(const TreeNodeEventHandler& handler) {
    on_poll_handler_ = handler;
    supports_on_poll_ = true;
    return this;
  }

  // Overrides the default-process-whole-sub-tree handler procedure called when
  // a on-change event is processed with a user-specified one.
  TreeNode* SetOnChangeHandler(const TreeNodeEventHandler& handler) {
    on_change_handler_ = handler;
    supports_on_change_ = true;
    return this;
  }

  // Overrides the default-do-not-register-for-any-event-type handler procedure
  // called when a on-change event is subscribed to with a user-specified one.
  TreeNode* SetOnChangeRegistration(const TreeNodeEventRegistration& handler) {
    on_change_registration_ = handler;
    return this;
  }

  // Overrides the default change-target-defined-mode-to-on-change-mode method
  // with a user-specified one.
  TreeNode* SetTargetDefinedMode(const TargetDefinedModeFunc& mode) {
    target_defined_mode_ = mode;
    return this;
  }

  // Returns a node that handles the YANG path starting from this node.
  const TreeNode* FindNodeOrNull(const ::gnmi::Path& path) const;

  // A generic method that checks if the subtree starting from this node
  // supports a particular type of events. The input parameter is a pointer to
  // the mameber variable that keeps information if this node supports the
  // requested type of events.
  bool AllSubtreeLeavesSupportOn(SupportsOnPtr supports_on) const {
    if (children_.empty()) {
      // This is a leaf - return what the flag says.
      return this->*supports_on;
    }
    // Not a leaf - check all leafs in this subtree. If even one of them does
    // not support this mode then the whole subtree does not support it!
    bool supported = true;
    for (const auto& entry : children_) {
      supported =
          supported && entry.second.AllSubtreeLeavesSupportOn(supports_on);
    }
    return supported;
  }

  // Returns true if the subtree starting from this node supports on-update
  // requests.
  bool AllSubtreeLeavesSupportOnUpdate() const {
    return AllSubtreeLeavesSupportOn(&TreeNode::supports_on_update_);
  }

  // Returns true if the subtree starting from this node supports on-update
  // requests.
  bool AllSubtreeLeavesSupportOnReplace() const {
    return AllSubtreeLeavesSupportOn(&TreeNode::supports_on_replace_);
  }

  // Returns true if the subtree starting from this node supports on-delete
  // requests.
  bool AllSubtreeLeavesSupportOnDelete() const {
    return AllSubtreeLeavesSupportOn(&TreeNode::supports_on_delete_);
  }

  // Returns true if the subtree starting from this node supports on-timer
  // events.
  bool AllSubtreeLeavesSupportOnTimer() const {
    return AllSubtreeLeavesSupportOn(&TreeNode::supports_on_timer_);
  }

  // Returns true if the subtree starting from this node supports on-poll
  // events.
  bool AllSubtreeLeavesSupportOnPoll() const {
    return AllSubtreeLeavesSupportOn(&TreeNode::supports_on_poll_);
  }

  // Returns true if the subtree starting from this node supports on-change
  // events.
  bool AllSubtreeLeavesSupportOnChange() const {
    return AllSubtreeLeavesSupportOn(&TreeNode::supports_on_change_);
  }

  // Returns a functor that will execute handlers of this node.
  GnmiSetHandler GetOnUpdateHandler() const {
    return
        [this](const ::gnmi::Path& path, const ::google::protobuf::Message& val,
               CopyOnWriteChassisConfig* config) {
          return on_update_handler_(path, val, config);
        };
  }

  // Returns a functor that will execute handlers of this node.
  GnmiSetHandler GetOnReplaceHandler() const {
    return
        [this](const ::gnmi::Path& path, const ::google::protobuf::Message& val,
               CopyOnWriteChassisConfig* config) {
          return on_replace_handler_(path, val, config);
        };
  }

  // Returns a functor that will execute handlers of this node.
  GnmiDeleteHandler GetOnDeleteHandler() const {
    return [this](const ::gnmi::Path& path, CopyOnWriteChassisConfig* config) {
      return on_delete_handler_(path, config);
    };
  }

  // Returns a functor that will execute handlers of this node and its children.
  GnmiEventHandler GetOnTimerHandler() const {
    return [this](const GnmiEvent& event, GnmiSubscribeStream* stream) {
      return VisitThisNodeAndItsChildren(&TreeNode::on_timer_handler_, event,
                                         this->GetPath(), stream);
    };
  }

  // Returns a functor that will execute handlers of this node and its children.
  GnmiEventHandler GetOnChangeHandler() const {
    return [this](const GnmiEvent& event, GnmiSubscribeStream* stream) {
      return VisitThisNodeAndItsChildren(&TreeNode::on_change_handler_, event,
                                         this->GetPath(), stream);
    };
  }

  // Returns a functor that will execute handlers of this node and its children.
  GnmiEventHandler GetOnPollHandler() const {
    return [this](const GnmiEvent& event, GnmiSubscribeStream* stream) {
      return VisitThisNodeAndItsChildren(&TreeNode::on_poll_handler_, event,
                                         this->GetPath(), stream);
    };
  }

  // Returns a functor that will register the on_change handler of this node for
  // the event type(s) that are handled by it.
  ::util::Status DoOnChangeRegistration(
      const EventHandlerRecordPtr& record) const {
    return RegisterThisNodeAndItsChildren(record);
  }

  // Modifies 'subscription' to be this leaf's preferred subscription mode.
  // As each node can have different requirements on how the TARGET_DEFINED
  // subscription request should be modified, this method calls the
  // target_defined_mode_ functor to modify the 'subscription` protobuf.
  ::util::Status ApplyTargetDefinedModeToSubscription(
      ::gnmi::Subscription* subscription) const {
    return target_defined_mode_(subscription);
  }

  const TreeNode& parent() const { return *parent_; }
  const std::string& name() const { return name_; }

  // Returns path from root to this node.
  ::gnmi::Path GetPath() const;

  std::map<std::string, TreeNode> children_;

 private:
  using TreeNodeEventHandlerPtr = TreeNodeEventHandler TreeNode::*;

  // Traverses the whole subtree starting from this node.
  // This method is used to visit all subtree nodes and execute handler functor
  // - this implements the expected behavior when a client subscribes to a node
  // that is not a leaf.
  ::util::Status VisitThisNodeAndItsChildren(
      const TreeNodeEventHandlerPtr& handler, const GnmiEvent& event,
      const ::gnmi::Path& path, GnmiSubscribeStream* stream) const;
  // Traverses the whole subtree starting from this node.
  // This method is used to visit all subtree nodes and execute registration
  // functor - this implements the expected behavior when a client subscribes in
  // STREAM:ON_CHANGE mode to a node that is not a leaf.
  ::util::Status RegisterThisNodeAndItsChildren(
      const EventHandlerRecordPtr& record) const;

  bool IsAKey() { return is_name_a_key_; }

  // A Mutex used to guard access to the handlers.
  mutable absl::Mutex access_lock_;

  TreeNodeEventHandler on_timer_handler_ =
      [](const GnmiEvent&, const ::gnmi::Path&, GnmiSubscribeStream*) {
        // Intermediate node. No real processing but needs to
        // return OK so its children are processed.
        return ::util::OkStatus();
      };
  TreeNodeEventHandler on_poll_handler_ =
      [](const GnmiEvent&, const ::gnmi::Path&, GnmiSubscribeStream*) {
        // Intermediate node. No real processing but needs to
        // return OK so its children are processed.
        return ::util::OkStatus();
      };
  TreeNodeEventHandler on_change_handler_ =
      [](const GnmiEvent&, const ::gnmi::Path&, GnmiSubscribeStream*) {
        // Intermediate node. No real processing but needs to
        // return OK so its children are processed.
        return ::util::OkStatus();
      };
  TreeNodeEventRegistration on_change_registration_ =
      [](const EventHandlerRecordPtr& record) {
        // Intermediate node. No GnmiEvent types to subscribe for.
        return ::util::OkStatus();
      };
  TargetDefinedModeFunc target_defined_mode_ =
      [](::gnmi::Subscription* subscription) {
        // In most cases the TARGET_DEFINED mode is ON_CHANGE mode as this mode
        // is the least resource-hungry.
        subscription->set_mode(::gnmi::SubscriptionMode::ON_CHANGE);
        subscription->set_sample_interval(0);
        subscription->set_heartbeat_interval(0);
        subscription->set_suppress_redundant(false);
        return ::util::OkStatus();
      };
  TreeNodeSetHandler on_update_handler_ =
      [](const ::gnmi::Path& path, const ::google::protobuf::Message&,
         CopyOnWriteChassisConfig*) -> ::util::Status {
    return MAKE_ERROR(ERR_FEATURE_UNAVAILABLE)
           << "Unsupported mode: UPDATE for: '" << path.ShortDebugString()
           << "'";
  };
  TreeNodeSetHandler on_replace_handler_ =
      [](const ::gnmi::Path& path, const ::google::protobuf::Message&,
         CopyOnWriteChassisConfig*) -> ::util::Status {
    return MAKE_ERROR(ERR_FEATURE_UNAVAILABLE)
           << "Unsupported mode: REPLACE for: '" << path.ShortDebugString()
           << "'";
  };
  TreeNodeDeleteHandler on_delete_handler_ =
      [](const ::gnmi::Path& path,
         CopyOnWriteChassisConfig*) -> ::util::Status {
    return MAKE_ERROR() << "unsupported mode: DELETE for: '"
                        << path.ShortDebugString() << "'";
  };
  const TreeNode* parent_;
  std::string name_;
  // Some nodes are mapped to ::gnmi::PathElem 'name' key value. This variable
  // is used to mark them as such.
  bool is_name_a_key_ = false;
  bool supports_on_timer_;
  bool supports_on_change_;
  bool supports_on_poll_;
  bool supports_on_update_;
  bool supports_on_replace_;
  bool supports_on_delete_;

  friend class stratum::hal::YangParseTreeTest;
  friend class stratum::hal::SubscriptionTestBase;
};

// A class implementing a YANG model tree. It uses TreeNode objects to
// represents nodes and leafs of the tree and provides additional methods to
// work with the tree.
class YangParseTree {
 public:
  explicit YangParseTree(BfChassisManager* bf_chassis_manager)
      LOCKS_EXCLUDED(root_access_lock_);
  virtual ~YangParseTree() {}

  // Registers a writer for sending gNMI events.
  virtual ::util::Status RegisterEventNotifyWriter(
      std::shared_ptr<WriterInterface<GnmiEventPtr>> writer) {
    absl::WriterMutexLock r(&root_access_lock_);

    gnmi_event_writer_ = std::move(writer);
    return ::util::OkStatus();
  }

  // Unregisters the previously registered event notify writer after calling
  // RegisterEventNotifyWriter().
  virtual ::util::Status UnregisterEventNotifyWriter() {
    absl::WriterMutexLock r(&root_access_lock_);

    gnmi_event_writer_ = nullptr;
    return ::util::OkStatus();
  }

  // Add supported leaf handles for one particular interface like xe-1/1/1.
  void AddSubtreeInterfaceFromSingleton(const SingletonPort& singleton,
                                        const NodeConfigParams& node_config)
      EXCLUSIVE_LOCKS_REQUIRED(root_access_lock_);
  // Add supported leaf handles for one particular interface like xe-1/1/1.
  void AddSubtreeInterfaceFromOptical(const OpticalNetworkInterface& optical)
      EXCLUSIVE_LOCKS_REQUIRED(root_access_lock_);
  // Add supported leaf handles for one particular interface like xe-1/1/1.
  void AddSubtreeInterfaceFromTrunk(const std::string& name, uint64 node_id,
                                    uint32 port_id,
                                    const NodeConfigParams& node_config)
      EXCLUSIVE_LOCKS_REQUIRED(root_access_lock_);
  // Add supported leaf handles for the case of interfaces[name=*] (all known
  // interfaces).
  void AddSubtreeAllInterfaces() EXCLUSIVE_LOCKS_REQUIRED(root_access_lock_);
  // Enable
  // * /components/component[name=*]/name
  // * /components/component/*
  // paths discovering.
  void AddSubtreeAllComponents() EXCLUSIVE_LOCKS_REQUIRED(root_access_lock_);

  // Add supported leaf handles for a node.
  void AddSubtreeNode(const Node& node)
      EXCLUSIVE_LOCKS_REQUIRED(root_access_lock_);

  // Add supported leaf handles for the chassis.
  void AddSubtreeChassis(const Chassis& chassis)
      EXCLUSIVE_LOCKS_REQUIRED(root_access_lock_);

  // Add supported leaf handles for the system.
  void AddSubtreeSystem() EXCLUSIVE_LOCKS_REQUIRED(root_access_lock_);

  // Configure the root element.
  void AddRoot() EXCLUSIVE_LOCKS_REQUIRED(root_access_lock_);

  // Returns a node that handles the YANG path.
  const TreeNode* FindNodeOrNull(const ::gnmi::Path& path) const
      LOCKS_EXCLUDED(root_access_lock_);

  // Returns the root node of the parse tree. Access to this node is useful when
  // an action on all nodes is needed.
  const TreeNode* GetRoot() const LOCKS_EXCLUDED(root_access_lock_);

  BfChassisManager* GetBfChassisManager() LOCKS_EXCLUDED(root_access_lock_) {
    absl::WriterMutexLock r(&root_access_lock_);

    return bf_chassis_manager_;
  }

  // A getter providing a functor setting TARGET_DEFINED mode of a leaf to be
  // STREAM:SAMPLE.
  const TreeNode::TargetDefinedModeFunc& GetStreamSampleModeFunc() {
    return stream_sample_mode_;
  }

  // A help method that is used to send notifications that a leaf has changed
  // using a channel between YangParseTree object and GnmiPublisher objest.
  virtual void SendNotification(const GnmiEventPtr& event)
      LOCKS_EXCLUDED(root_access_lock_);

  // An action that modifies the tree to reflect new configuration.
  void ProcessPushedConfig(const ConfigHasBeenPushedEvent& change)
      LOCKS_EXCLUDED(root_access_lock_);

 protected:
  using Action = std::function<void()>;

  // Adds node to a tree at specified path.
  TreeNode* AddNode(const ::gnmi::Path& path)
      EXCLUSIVE_LOCKS_REQUIRED(root_access_lock_);

  // Copies a subtree.
  ::util::Status CopySubtree(const ::gnmi::Path& from, const ::gnmi::Path& to)
      EXCLUSIVE_LOCKS_REQUIRED(root_access_lock_);

  // A helper method for checking if the name of a TreeNode is a wildcard.
  // It is used while processing requests for multiple children to skip nodes
  // whose processing would create an infinite loop as the wildcard nodes are
  // stored in the parse tree the same way as the regular ones.
  bool IsWildcard(const std::string& name) const;

  // A helper function. Finds a node specified by 'path' and then for all
  // non-wildcard children finds leaf specified by 'subpath' and executes
  // 'action' on that leaf.
  ::util::Status PerformActionForAllNonWildcardNodes(
      const gnmi::Path& path, const gnmi::Path& subpath,
      const std::function<::util::Status(const TreeNode& leaf)>& action) const
      EXCLUSIVE_LOCKS_REQUIRED(root_access_lock_);

  BfChassisManager* bf_chassis_manager_ GUARDED_BY(root_access_lock_);

  // A channel between YangParseTree object and GnmiPublisher objest.
  // It is used to send notifications that a leaf has changed.
  std::shared_ptr<WriterInterface<GnmiEventPtr>> gnmi_event_writer_
      GUARDED_BY(root_access_lock_);

  TreeNode root_ GUARDED_BY(root_access_lock_);
  // A Mutex used to guard access to the root.
  mutable absl::Mutex root_access_lock_;

  // In most cases the TARGET_DEFINED mode is ON_CHANGE mode as this mode
  // is the least resource-hungry. But to make the gNMI demo more realistic it
  // is changed to SAMPLE with the period of 1s.
  // TODO(unknown): remove/update this functor once the support for reading
  // counters is implemented.
  TreeNode::TargetDefinedModeFunc stream_sample_mode_ =
      [](::gnmi::Subscription* subscription) {
        subscription->set_mode(::gnmi::SubscriptionMode::SAMPLE);
        subscription->set_sample_interval(1000);  // 1sec
        subscription->set_heartbeat_interval(0);
        subscription->set_suppress_redundant(false);
        return ::util::OkStatus();
      };

  friend class stratum::hal::YangParseTreePaths;
  friend class stratum::hal::YangParseTreeTest;
};

// A class that implements a channel that is used to return the data values
// from the HAL to the YANG tree node handlers.
// While all YANG tree node handlers receive data enveloped into
// the DataResponse message, the actual data has to be retrieved from
// request-specific field. To provide the required flexibility this class uses
// a 'Worker' functors that are defined in-place and update local variables.
class DataResponseWriter : public WriterInterface<DataResponse> {
 public:
  using Worker = std::function<bool(const DataResponse& resp)>;
  explicit DataResponseWriter(const Worker& worker) : worker_(worker) {}

  // The only work method defined by the interface - it is called every time
  // there is a data to be processed.
  bool Write(const DataResponse& resp) override { return worker_(resp); }

 private:
  // A functor that handles the received data.
  Worker worker_;
};

}  // namespace hal
}  // namespace stratum

#endif  // STRATUM_HAL_LIB_COMMON_YANG_PARSE_TREE_H_
