// Copyright 2018 Google LLC
// Copyright 2018-present Open Networking Foundation
// Copyright(c) 2021 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0

#ifndef STRATUM_HAL_LIB_COMMON_GNMI_PUBLISHER_H_
#define STRATUM_HAL_LIB_COMMON_GNMI_PUBLISHER_H_

#include <pthread.h>
#include <time.h>

#include <memory>
#include <string>
#include <algorithm>
#include <map>

#include "p4/gnmi/gnmi.grpc.pb.h"
// FIXME(boc) is this required?
#include "stratum/glue/logging.h"
#include "stratum/glue/status/status.h"
#include "stratum/glue/status/status_macros.h"
#include "stratum/hal/lib/common/gnmi_events.h"
#include "stratum/lib/timer_daemon.h"
#include "stratum/public/lib/error.h"
#include "absl/synchronization/mutex.h"
#include "absl/container/flat_hash_map.h"
#include "stratum/glue/gtl/map_util.h"
#include "yang_parse_tree.h"
#include "bfIntf/bf_chassis_manager.h"

namespace stratum {
namespace hal {

class ConfigMonitoringServiceTest;
class SubscriptionTest;

// A container for all paremeters needed to define how often a subscriber wants
// to receive streamed data.
class Frequency {
 public:
  uint64 delay_ms_;
  uint64 period_ms_;
  uint64 heartbeat_ms_;

 protected:
  Frequency(uint64 delay_ms, uint64 period_ms, uint64 heartbeat_ms)
      : delay_ms_(delay_ms),
        period_ms_(period_ms),
        heartbeat_ms_(heartbeat_ms) {}
};

// Specialization of the Frequency container to be used by subscriptions that
// require updates every 'period_ms' milliseconds.
class Periodic : public Frequency {
 public:
  explicit Periodic(uint64 period_ms) : Frequency(0, period_ms, 0) {}
};

// Specialization of the Frequency container to be used by subscriptions that
// require updates every 'period_ms' milliseconds. The current state is _only_
// reported if there is change in the value of the node unless since last update
// 'heartbeat_ms' milliseconds have elapsed.
class PeriodicWithHeartbeat : public Frequency {
 public:
  PeriodicWithHeartbeat(uint64 period_ms, uint64 heartbeat_ms)
      : Frequency(0, period_ms, heartbeat_ms) {}
};

// The main class responsible for handling all aspects of gNMI subscriptions and
// notifications.
class GnmiPublisher {
 protected:
  using SupportOnPtr = bool (TreeNode::*)() const;
  using GetHandlerFunc = GnmiEventHandler (TreeNode::*)() const;

 public:
  static constexpr int kMaxGnmiEventDepth = 256;

  // Constructor.
  explicit GnmiPublisher(BfChassisManager*);

  virtual ~GnmiPublisher();

  virtual ::util::Status HandleUpdate(const ::gnmi::Path& path,
                                      const ::google::protobuf::Message& val,
                                      CopyOnWriteChassisConfig* config)
      LOCKS_EXCLUDED(access_lock_);

  virtual ::util::Status HandleReplace(const ::gnmi::Path& path,
                                       const ::google::protobuf::Message& val,
                                       CopyOnWriteChassisConfig* config)
      LOCKS_EXCLUDED(access_lock_);

  virtual ::util::Status HandleDelete(const ::gnmi::Path& path,
                                      CopyOnWriteChassisConfig* config)
      LOCKS_EXCLUDED(access_lock_);

  ::util::Status HandleChange(const GnmiEvent& event)
      LOCKS_EXCLUDED(access_lock_);

  virtual ::util::Status HandlePoll(const SubscriptionHandle& handle)
      LOCKS_EXCLUDED(access_lock_);

  virtual ::util::Status SubscribePeriodic(const Frequency& freq,
                                           const ::gnmi::Path& path,
                                           GnmiSubscribeStream* stream,
                                           SubscriptionHandle* h);

  virtual ::util::Status SubscribePoll(const ::gnmi::Path& path,
                                       GnmiSubscribeStream* stream,
                                       SubscriptionHandle* h)
      LOCKS_EXCLUDED(access_lock_);

  virtual ::util::Status SubscribeOnChange(const ::gnmi::Path& path,
                                           GnmiSubscribeStream* stream,
                                           SubscriptionHandle* h)
      LOCKS_EXCLUDED(access_lock_);

  // One of the subscription modes, TARGET_DEFINED, leaves the decision of how
  // to treat the received subscription request to the switch.
  // When such request is received this method is called and the request is
  // passed to the node implementating 'path' to modify the 'subscription'
  // request to be what the switch would like it to be.
  // Note that this method does not check if mode in 'request' is set to
  // TARGET_DEFINED.
  virtual ::util::Status UpdateSubscriptionWithTargetSpecificModeSpecification(
      const ::gnmi::Path& path, ::gnmi::Subscription* subscription)
      LOCKS_EXCLUDED(access_lock_);

  virtual ::util::Status UnSubscribe(const SubscriptionHandle& h)
      LOCKS_EXCLUDED(access_lock_);

  // The method sends a gNMI message denoting the end of initial set of values.
  virtual ::util::Status SendSyncResponse(GnmiSubscribeStream* stream);

  // Method creating the channel to be used to receive notifications from
  // the switch.
  virtual ::util::Status RegisterEventWriter() LOCKS_EXCLUDED(access_lock_);

  // A method deleting the channel used to receive notifications from
  // the switch and cleaning-up.
  virtual ::util::Status UnregisterEventWriter() LOCKS_EXCLUDED(access_lock_);

 private:
  // ReaderArgs encapsulates the arguments for a Channel reader thread.
  template <typename T>
  struct ReaderArgs {
    GnmiPublisher* manager;
    std::unique_ptr<ChannelReader<T>> reader;
  };

  // A family of helper methods that simplify registration of event handlers
  // with correct event handler list.
  template <typename E>
  ::util::Status Register(const EventHandlerRecordPtr& record) {
    return EventHandlerList<E>::GetInstance()->Register(record);
  }

  // An internal method that handles an event in the context of particular event
  // handler.
  ::util::Status HandleEvent(const GnmiEvent& event,
                             const EventHandlerRecordPtr& h)
      LOCKS_EXCLUDED(access_lock_);

  // A generic method handling all types of subscriptions. Requires long list of
  // parameters, so, it has been hidden here and specialized methods calling it
  // have been exposed as public interface.
  ::util::Status Subscribe(const SupportOnPtr& supports_on,
                           const GetHandlerFunc& get_handler,
                           const ::gnmi::Path& path,
                           GnmiSubscribeStream* stream, SubscriptionHandle* h)
      LOCKS_EXCLUDED(access_lock_);

  // A handler of events received over the event_channel_ channel.
  void ReadGnmiEvents(
      const std::unique_ptr<ChannelReader<GnmiEventPtr>>& reader)
      LOCKS_EXCLUDED(access_lock_);

  // A code executed by the thread waiting for events transmitted over
  // the event_channel_ channel.
  static void* ThreadReadGnmiEvents(void* arg) LOCKS_EXCLUDED(access_lock_);

  // A pointer to implementation of the Switch Interface - the API used to
  // communicate with the switch.
  BfChassisManager* bf_chassis_manager_ GUARDED_BY(access_lock_);

  // A Mutex used to guard access to the list of pointers to handlers.
  mutable absl::Mutex access_lock_;

  // A tree that is used to map a YAML tree path into a functor that handles
  // that node.
  YangParseTree parse_tree_ GUARDED_BY(access_lock_);

  // Channel for receiving transceiver events from the SwitchInterface.
  std::shared_ptr<Channel<GnmiEventPtr>> event_channel_
      GUARDED_BY(access_lock_);

  // Special event handler that is called when a ConfigHasBeenPushedEvent event
  // is received.
  std::function<::util::Status(const GnmiEvent&, GnmiSubscribeStream*)>
      on_config_pushed_func_ GUARDED_BY(access_lock_) =
          [this](const GnmiEvent& event_base, GnmiSubscribeStream* stream)
              EXCLUSIVE_LOCKS_REQUIRED(access_lock_) {
                // Special case - change of configuration.
                // FIXME(boc) VLOG(1) does not appear to work inside of a lambda
                // VLOG(1) << "Configuration has changed.";
                // FIXME(boc) the following statement is a temporary hack
                if (FLAGS_v >= 1) LOG(INFO) << "Configuration has changed.";
                if (auto* event = dynamic_cast<const ConfigHasBeenPushedEvent*>(
                        &event_base)) {
                  parse_tree_.ProcessPushedConfig(*event);
                }
                return ::util::OkStatus();
              };  // NOLINT
  SubscriptionHandle on_config_pushed_;

  friend class ConfigMonitoringServiceTest;
  friend class SubscriptionTestBase;
};

// In order to use ::gnmi::Path as a key in std::map<> a comparator functor has
// to be defined.
struct PathComparator {
  bool operator()(const ::gnmi::Path& lhs, const ::gnmi::Path& rhs) const {
    // Only elements that are present in both paths can be compared.
    int min_size = std::min(lhs.elem_size(), rhs.elem_size());
    for (int i = 0; i < min_size; ++i) {
      int result = 0;
      if ((result = lhs.elem(i).name().compare(rhs.elem(i).name())) != 0) {
        // The elements of the path at index 'i' differ!
        return (result < 0);
      }
      auto* lhs_key = gtl::FindOrNull(lhs.elem(i).key(), "name");
      auto* rhs_key = gtl::FindOrNull(rhs.elem(i).key(), "name");
      if (lhs_key == nullptr && rhs_key == nullptr) {
        // No key in bot elements!
        continue;
      }
      if (lhs_key != nullptr && rhs_key != nullptr) {
        // Both have keys!
        if ((result = lhs_key->compare(*rhs_key)) != 0) {
          // The keys of elements of the path at index 'i' differ!
          return (result < 0);
        }
        continue;
      }
      // Only one element has a key. So if lhs has a key then (lhs < rhs)
      // evaluates to 'false'.
      return (lhs_key != nullptr);
    }
    if (lhs.elem_size() == rhs.elem_size()) {
      // All elements of both paths are the same. So (lhs < rhs) evaluates to
      // 'false'.
      return false;
    } else {
      // One path is longer. The shorter path is 'smaller'.
      return lhs.elem_size() < rhs.elem_size();
    }
  }
};

// A compare operator for ::gnmi::Path objects.
inline bool operator==(const ::gnmi::Path& lhs, const ::gnmi::Path& rhs) {
  static PathComparator c;
  // The PathComparator supports only one comparison: lhs < rhs.
  return c(lhs, rhs) == c(rhs, lhs);
}

// A map mapping ::gnmi::Path to GnmiPublisher::Handle. Due to not being a basic
// type, ::gnmi::Path requires a comparator functor (the third template
// parameter).
using PathToHandleMap =
    std::map<::gnmi::Path, SubscriptionHandle, PathComparator>;

// A helper that initializes correctly ::gnmi::Path.
class GetPath {
 public:
  explicit GetPath(const std::string& name) {
    auto* elem = path_.add_elem();
    elem->set_name(name);
  }

  GetPath(const std::string& name, const std::string& search) {
    auto* elem = path_.add_elem();
    elem->set_name(name);
    (*elem->mutable_key())["name"] = search;
  }

  GetPath() {}

  GetPath operator()(const std::string& name) {
    auto* elem = path_.add_elem();
    elem->set_name(name);
    return *this;
  }

  GetPath operator()(const std::string& name, const std::string& search) {
    auto* elem = path_.add_elem();
    elem->set_name(name);
    (*elem->mutable_key())["name"] = search;
    return *this;
  }

  const ::gnmi::Path& operator()() { return path_; }

 private:
  ::gnmi::Path path_;
};

}  // namespace hal
}  // namespace stratum

#endif  // STRATUM_HAL_LIB_COMMON_GNMI_PUBLISHER_H_
