// Copyright 2018 Google LLC
// Copyright 2018-present Open Networking Foundation
// Copyright(c) 2021 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0

#include "gnmi_publisher.h"

#include <list>
#include <string>
#include <utility>

#include "absl/synchronization/mutex.h"
#include "p4/gnmi/gnmi.pb.h"
#include "stratum/glue/gtl/map_util.h"
#include "stratum/hal/lib/common/channel_writer_wrapper.h"
#include "yang_parse_tree_paths.h"

namespace stratum {
namespace hal {

GnmiPublisher::GnmiPublisher(BfChassisManager *bf_chassis_manager)
    : bf_chassis_manager_(ABSL_DIE_IF_NULL(bf_chassis_manager)),
      parse_tree_(ABSL_DIE_IF_NULL(bf_chassis_manager)),
      event_channel_(nullptr),
      on_config_pushed_(
          new EventHandlerRecord(on_config_pushed_func_, nullptr)) {
  Register<ConfigHasBeenPushedEvent>(EventHandlerRecordPtr(on_config_pushed_))
      .IgnoreError();
}

GnmiPublisher::~GnmiPublisher() {}

::util::Status GnmiPublisher::HandleUpdate(
    const ::gnmi::Path& path, const ::google::protobuf::Message& val,
    CopyOnWriteChassisConfig* config) {
  absl::WriterMutexLock l(&access_lock_);

  // Map the input path to the supported one - walk the tree of known elements
  // element by element starting from the root and if the element is found the
  // move to the next one. If not found, return an error.
  const TreeNode* node = parse_tree_.FindNodeOrNull(path);
  if (node == nullptr) {
    // Ooops... This path is not supported.
    return MAKE_ERROR(ERR_INVALID_PARAM)
           << "The path (" << path.ShortDebugString() << ") is unsupported!";
  }

  // Call the handler and return the status of this call.
  return node->GetOnUpdateHandler()(path, val, config);
}

::util::Status GnmiPublisher::HandleReplace(
    const ::gnmi::Path& path, const ::google::protobuf::Message& val,
    CopyOnWriteChassisConfig* config) {
  absl::WriterMutexLock l(&access_lock_);

  // Map the input path to the supported one - walk the tree of known elements
  // element by element starting from the root and if the element is found the
  // move to the next one. If not found, return an error.
  const TreeNode* node = parse_tree_.FindNodeOrNull(path);
  if (node == nullptr) {
    // Ooops... This path is not supported.
    return MAKE_ERROR(ERR_INVALID_PARAM)
           << "The path (" << path.ShortDebugString() << ") is unsupported!";
  }

  // Call the handler and return the status of this call.
  return node->GetOnReplaceHandler()(path, val, config);
}

::util::Status GnmiPublisher::HandleDelete(const ::gnmi::Path& path,
                                           CopyOnWriteChassisConfig* config) {
  absl::WriterMutexLock l(&access_lock_);

  // Map the input path to the supported one - walk the tree of known elements
  // element by element starting from the root and if the element is found the
  // move to the next one. If not found, return an error.
  const TreeNode* node = parse_tree_.FindNodeOrNull(path);
  if (node == nullptr) {
    // Ooops... This path is not supported.
    return MAKE_ERROR(ERR_INVALID_PARAM)
           << "The path (" << path.ShortDebugString() << ") is unsupported!";
  }

  // Call the handler and return the status of this call.
  return node->GetOnDeleteHandler()(path, config);
}

::util::Status GnmiPublisher::HandleChange(const GnmiEvent& event) {
  absl::WriterMutexLock l(&access_lock_);

  return event.Process();
}

::util::Status GnmiPublisher::HandleEvent(
    const GnmiEvent& event, const std::weak_ptr<EventHandlerRecord>& h) {
  absl::WriterMutexLock l(&access_lock_);

  // In order to reference a weak pointer, first it has to be used to create a
  // shared pointer.
  if (std::shared_ptr<EventHandlerRecord> handler = h.lock()) {
    RETURN_IF_ERROR((*handler)(event));
  }
  return ::util::OkStatus();
}

::util::Status GnmiPublisher::HandlePoll(const SubscriptionHandle& handle) {
  absl::WriterMutexLock l(&access_lock_);

  return (*handle)(PollEvent());
}

::util::Status GnmiPublisher::SubscribePeriodic(const Frequency& freq,
                                                const ::gnmi::Path& path,
                                                GnmiSubscribeStream* stream,
                                                SubscriptionHandle* h) {
  auto status = Subscribe(&TreeNode::AllSubtreeLeavesSupportOnTimer,
                          &TreeNode::GetOnTimerHandler, path, stream, h);
  if (status != ::util::OkStatus()) {
    return status;
  }
  EventHandlerRecordPtr weak(*h);
  if (TimerDaemon::RequestPeriodicTimer(
          freq.delay_ms_, freq.period_ms_,
          [weak, this]() { return this->HandleEvent(TimerEvent(), weak); },
          (*h)->mutable_timer()) != ::util::OkStatus()) {
    return MAKE_ERROR(ERR_INTERNAL) << "Cannot start timer.";
  }
  // A handler has been successfully found and now it has to be registered in
  // the event handler list that handles timer events.
  return Register<TimerEvent>(weak);
}

::util::Status GnmiPublisher::SubscribePoll(const ::gnmi::Path& path,
                                            GnmiSubscribeStream* stream,
                                            SubscriptionHandle* h) {
  return Subscribe(&TreeNode::AllSubtreeLeavesSupportOnPoll,
                   &TreeNode::GetOnPollHandler, path, stream, h);
}

::util::Status GnmiPublisher::SubscribeOnChange(const ::gnmi::Path& path,
                                                GnmiSubscribeStream* stream,
                                                SubscriptionHandle* h) {
  auto status = Subscribe(&TreeNode::AllSubtreeLeavesSupportOnChange,
                          &TreeNode::GetOnChangeHandler, path, stream, h);
  if (status != ::util::OkStatus()) {
    return status;
  }
  // A handler has been successfully found and now it has to be registered in
  // all event handler lists that handle events of the type this handler is
  // prepared to handle.
  absl::WriterMutexLock l(&access_lock_);
  return parse_tree_.FindNodeOrNull(path)->DoOnChangeRegistration(
      EventHandlerRecordPtr(*h));
}

::util::Status GnmiPublisher::Subscribe(
    const SupportOnPtr& all_leaves_support_mode,
    const GetHandlerFunc& get_handler, const ::gnmi::Path& path,
    GnmiSubscribeStream* stream, SubscriptionHandle* h) {
  absl::WriterMutexLock l(&access_lock_);

  // Check input parameters.
  if (stream == nullptr) {
    return MAKE_ERROR(ERR_INVALID_PARAM) << "stream pointer is null!";
  }
  if (h == nullptr) {
    return MAKE_ERROR(ERR_INVALID_PARAM) << "handle pointer is null!";
  }
  if (path.elem_size() == 0) {
    return MAKE_ERROR(ERR_INVALID_PARAM) << "path is empty!";
  }
  // Map the input path to the supported one - walk the tree of known elements
  // element by element starting from the root and if the element is found the
  // move to the next one. If not found, return an error.
  const TreeNode* node = parse_tree_.FindNodeOrNull(path);
  if (node == nullptr) {
    // Ooops... This path is not supported.
    return MAKE_ERROR(ERR_INVALID_PARAM)
           << "The path (" << path.ShortDebugString() << ") is unsupported!";
  }
  if (!(node->*all_leaves_support_mode)()) {
    // Ooops... Not all leaves in this subtree support this mode!
    return MAKE_ERROR(ERR_INVALID_PARAM)
           << "Not all leaves on the path (" << path.ShortDebugString()
           << ") support this mode!";
  }
  // All good! Save the handler that handles this leaf.
  h->reset(new EventHandlerRecord((node->*get_handler)(), stream));
  return ::util::OkStatus();
}

::util::Status GnmiPublisher::UnSubscribe(const SubscriptionHandle& h) {
  absl::WriterMutexLock l(&access_lock_);
  // There is no way to match a subscription to a certain type of event.
  // Therefore we have to try removing it from every list we register events
  // on. Currently this is just TimerEvent.
  // FIXME: Add UnRegister calls for other EventHandlerLists in use.
  return EventHandlerList<TimerEvent>::GetInstance()->UnRegister(h);
}

::util::Status
GnmiPublisher::UpdateSubscriptionWithTargetSpecificModeSpecification(
    const ::gnmi::Path& path, ::gnmi::Subscription* subscription) {
  absl::WriterMutexLock l(&access_lock_);
  // Check input parameters.
  if (subscription == nullptr) {
    return MAKE_ERROR(ERR_INVALID_PARAM) << "subscription pointer is null!";
  }
  if (path.elem_size() == 0) {
    return MAKE_ERROR(ERR_INVALID_PARAM) << "path is empty!";
  }
  // Map the input path to the supported one - walk the tree of known elements,
  // element by element, starting from the root. If the element is found, move
  // to the next one. If not found, return an error.
  const TreeNode* node = parse_tree_.FindNodeOrNull(path);
  if (node == nullptr) {
    // Ooops... This path is not supported.
    return MAKE_ERROR(ERR_INVALID_PARAM)
           << "The path (" << path.ShortDebugString() << ") is unsupported!";
  }
  return node->ApplyTargetDefinedModeToSubscription(subscription);
}

::util::Status GnmiPublisher::SendSyncResponse(GnmiSubscribeStream* stream) {
  // Notify the client that all nodes have been processed.
  if (stream == nullptr) {
    LOG(ERROR) << "Message cannot be sent as the stream pointer is null!";
    return MAKE_ERROR(ERR_INTERNAL) << "stream pointer is null!";
  }
  return YangParseTreePaths::SendEndOfSeriesMessage(stream);
}

void GnmiPublisher::ReadGnmiEvents(
    const std::unique_ptr<ChannelReader<GnmiEventPtr>>& reader) {
  do {
    GnmiEventPtr event_ptr;
    // Block on the next event message from the Channel.
    int code = reader->Read(&event_ptr, absl::InfiniteDuration()).error_code();
    // Exit if the Channel is closed.
    if (code == ERR_CANCELLED) break;
    // Read should never timeout.
    if (code == ERR_ENTRY_NOT_FOUND) {
      LOG(ERROR) << "Read with infinite timeout failed with ENTRY_NOT_FOUND.";
      continue;
    }
    // Handle received message.
    ::util::Status status = HandleChange(*event_ptr);
    if (status != ::util::OkStatus()) LOG(ERROR) << status;
  } while (true);
}

void* GnmiPublisher::ThreadReadGnmiEvents(void* arg) {
  CHECK(arg != nullptr);
  // Retrieve arguments.
  auto* args = reinterpret_cast<ReaderArgs<GnmiEventPtr>*>(arg);
  GnmiPublisher* manager = args->manager;
  std::unique_ptr<ChannelReader<GnmiEventPtr>> reader = std::move(args->reader);
  delete args;
  manager->ReadGnmiEvents(reader);
  return nullptr;
}

::util::Status GnmiPublisher::RegisterEventWriter() {
  absl::WriterMutexLock l(&access_lock_);
  // If we have not done that yet, create notification event Channel, register
  // it, and create Reader thread.
  if (event_channel_ == nullptr && bf_chassis_manager_ != nullptr) {
    event_channel_ = Channel<GnmiEventPtr>::Create(kMaxGnmiEventDepth);
    // Create and register writer to channel with the BcmSdkInterface.
    auto writer = std::make_shared<ChannelWriterWrapper<GnmiEventPtr>>(
        ChannelWriter<GnmiEventPtr>::Create(event_channel_));
    RETURN_IF_ERROR(bf_chassis_manager_->RegisterEventNotifyWriter(writer));
    RETURN_IF_ERROR(parse_tree_.RegisterEventNotifyWriter(writer));
    // Create and hand-off Reader to new reader thread.
    pthread_t event_reader_tid;
    auto reader = ChannelReader<GnmiEventPtr>::Create(event_channel_);
    int ret =
        pthread_create(&event_reader_tid, nullptr, ThreadReadGnmiEvents,
                       new ReaderArgs<GnmiEventPtr>{this, std::move(reader)});
    if (ret != 0) {
      return MAKE_ERROR(ERR_INTERNAL)
             << "Failed to spawn gNMI event thread. Err: " << ret << ".";
    }
    // We don't care about the return value. The thread should exit following
    // the closing of the Channel in UnregisterEventWriter().
    ret = pthread_detach(event_reader_tid);
    if (ret != 0) {
      return MAKE_ERROR(ERR_INTERNAL)
             << "Failed to detach gNMI event thread. Err: " << ret << ".";
    }
  }

  return ::util::OkStatus();
}

::util::Status GnmiPublisher::UnregisterEventWriter() {
  absl::WriterMutexLock l(&access_lock_);
  ::util::Status status = ::util::OkStatus();
  // Unregister the Event Notify Channel from the SwitchInterface.
  if (event_channel_ == nullptr && bf_chassis_manager_ != nullptr) {
    APPEND_STATUS_IF_ERROR(status,
                           bf_chassis_manager_->UnregisterEventNotifyWriter());
    APPEND_STATUS_IF_ERROR(status, parse_tree_.UnregisterEventNotifyWriter());
    // Close Channel.
    if (!event_channel_->Close()) {
      ::util::Status error = MAKE_ERROR(ERR_INTERNAL)
                             << " Event Notify Channel is already closed.";
      APPEND_STATUS_IF_ERROR(status, error);
    }
    event_channel_ = nullptr;
  }

  return status;
}

}  // namespace hal
}  // namespace stratum
