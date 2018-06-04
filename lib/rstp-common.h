/*
 * Copyright (c) 2011-2015 M3S, Srl - Italy
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Rapid Spanning Tree Protocol (IEEE 802.1D-2004) common header file.
 *
 * Authors:
 *         Martino Fornasa <mf@fornasa.it>
 *         Daniele Venturino <daniele.venturino@m3s.it>
 *         Carlo Andreotti <c.andreotti@m3s.it>
 *
 * References to IEEE 802.1D-2004 standard are enclosed in square brackets.
 * E.g. [17.3], [Table 17-1], etc.
 *
 */

#ifndef RSTP_COMMON_H
#define RSTP_COMMON_H 1

#include "rstp.h"
#include <stdbool.h>
#include <stdint.h>
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "ovs-atomic.h"
#include "packets.h"

enum admin_port_state {
    RSTP_ADMIN_BRIDGE_PORT_STATE_DISABLED = 0,
    RSTP_ADMIN_BRIDGE_PORT_STATE_ENABLED = 1
};

enum oper_p2p_mac_state {
    RSTP_OPER_P2P_MAC_STATE_DISABLED = 0,
    RSTP_OPER_P2P_MAC_STATE_ENABLED = 1
};

/* State enumerations for state machines defined in rstp-state-machines.c */
enum port_receive_state_machine {
    PORT_RECEIVE_SM_INIT,
    PORT_RECEIVE_SM_DISCARD_EXEC,
    PORT_RECEIVE_SM_DISCARD,
    PORT_RECEIVE_SM_RECEIVE_EXEC,
    PORT_RECEIVE_SM_RECEIVE
};
enum port_transmit_state_machine {
    PORT_TRANSMIT_SM_INIT,
    PORT_TRANSMIT_SM_TRANSMIT_INIT_EXEC,
    PORT_TRANSMIT_SM_TRANSMIT_INIT,
    PORT_TRANSMIT_SM_TRANSMIT_PERIODIC_EXEC,
    PORT_TRANSMIT_SM_TRANSMIT_PERIODIC,
    PORT_TRANSMIT_SM_IDLE_EXEC,
    PORT_TRANSMIT_SM_IDLE,
    PORT_TRANSMIT_SM_TRANSMIT_CONFIG_EXEC,
    PORT_TRANSMIT_SM_TRANSMIT_CONFIG,
    PORT_TRANSMIT_SM_TRANSMIT_TCN_EXEC,
    PORT_TRANSMIT_SM_TRANSMIT_TCN,
    PORT_TRANSMIT_SM_TRANSMIT_RSTP_EXEC,
    PORT_TRANSMIT_SM_TRANSMIT_RSTP
};
enum bridge_detection_state_machine {
    BRIDGE_DETECTION_SM_INIT,
    BRIDGE_DETECTION_SM_EDGE_EXEC,
    BRIDGE_DETECTION_SM_EDGE,
    BRIDGE_DETECTION_SM_NOT_EDGE_EXEC,
    BRIDGE_DETECTION_SM_NOT_EDGE
};
enum port_protocol_migration_state_machine {
    PORT_PROTOCOL_MIGRATION_SM_INIT,
    PORT_PROTOCOL_MIGRATION_SM_CHECKING_RSTP_EXEC,
    PORT_PROTOCOL_MIGRATION_SM_CHECKING_RSTP,
    PORT_PROTOCOL_MIGRATION_SM_SELECTING_STP_EXEC,
    PORT_PROTOCOL_MIGRATION_SM_SELECTING_STP,
    PORT_PROTOCOL_MIGRATION_SM_SENSING_EXEC,
    PORT_PROTOCOL_MIGRATION_SM_SENSING
};
enum port_information_state_machine {
    PORT_INFORMATION_SM_INIT,
    PORT_INFORMATION_SM_DISABLED_EXEC,
    PORT_INFORMATION_SM_DISABLED,
    PORT_INFORMATION_SM_AGED_EXEC,
    PORT_INFORMATION_SM_AGED,
    PORT_INFORMATION_SM_UPDATE_EXEC,
    PORT_INFORMATION_SM_UPDATE,
    PORT_INFORMATION_SM_CURRENT_EXEC,
    PORT_INFORMATION_SM_CURRENT,
    PORT_INFORMATION_SM_RECEIVE_EXEC,
    PORT_INFORMATION_SM_RECEIVE,
    PORT_INFORMATION_SM_OTHER_EXEC,
    PORT_INFORMATION_SM_OTHER,
    PORT_INFORMATION_SM_NOT_DESIGNATED_EXEC,
    PORT_INFORMATION_SM_NOT_DESIGNATED,
    PORT_INFORMATION_SM_INFERIOR_DESIGNATED_EXEC,
    PORT_INFORMATION_SM_INFERIOR_DESIGNATED,
    PORT_INFORMATION_SM_REPEATED_DESIGNATED_EXEC,
    PORT_INFORMATION_SM_REPEATED_DESIGNATED,
    PORT_INFORMATION_SM_SUPERIOR_DESIGNATED_EXEC,
    PORT_INFORMATION_SM_SUPERIOR_DESIGNATED
};
enum port_role_selection_state_machine {
    PORT_ROLE_SELECTION_SM_INIT,
    PORT_ROLE_SELECTION_SM_INIT_BRIDGE_EXEC,
    PORT_ROLE_SELECTION_SM_INIT_BRIDGE,
    PORT_ROLE_SELECTION_SM_ROLE_SELECTION_EXEC,
    PORT_ROLE_SELECTION_SM_ROLE_SELECTION
};
enum port_role_transition_state_machine {
    PORT_ROLE_TRANSITION_SM_INIT,
    PORT_ROLE_TRANSITION_SM_INIT_PORT_EXEC,
    PORT_ROLE_TRANSITION_SM_DISABLE_PORT_EXEC,
    PORT_ROLE_TRANSITION_SM_DISABLE_PORT,
    PORT_ROLE_TRANSITION_SM_DISABLED_PORT_EXEC,
    PORT_ROLE_TRANSITION_SM_DISABLED_PORT,
    PORT_ROLE_TRANSITION_SM_ROOT_PORT_EXEC,
    PORT_ROLE_TRANSITION_SM_ROOT_PORT,
    PORT_ROLE_TRANSITION_SM_REROOT_EXEC,
    PORT_ROLE_TRANSITION_SM_ROOT_AGREED_EXEC,
    PORT_ROLE_TRANSITION_SM_ROOT_PROPOSED_EXEC,
    PORT_ROLE_TRANSITION_SM_ROOT_FORWARD_EXEC,
    PORT_ROLE_TRANSITION_SM_ROOT_LEARN_EXEC,
    PORT_ROLE_TRANSITION_SM_REROOTED_EXEC,
    PORT_ROLE_TRANSITION_SM_DESIGNATED_PORT_EXEC,
    PORT_ROLE_TRANSITION_SM_DESIGNATED_PORT,
    PORT_ROLE_TRANSITION_SM_DESIGNATED_RETIRED_EXEC,
    PORT_ROLE_TRANSITION_SM_DESIGNATED_SYNCED_EXEC,
    PORT_ROLE_TRANSITION_SM_DESIGNATED_PROPOSE_EXEC,
    PORT_ROLE_TRANSITION_SM_DESIGNATED_FORWARD_EXEC,
    PORT_ROLE_TRANSITION_SM_DESIGNATED_LEARN_EXEC,
    PORT_ROLE_TRANSITION_SM_DESIGNATED_DISCARD_EXEC,
    PORT_ROLE_TRANSITION_SM_ALTERNATE_PORT_EXEC,
    PORT_ROLE_TRANSITION_SM_ALTERNATE_PORT,
    PORT_ROLE_TRANSITION_SM_ALTERNATE_AGREED_EXEC,
    PORT_ROLE_TRANSITION_SM_ALTERNATE_PROPOSED_EXEC,
    PORT_ROLE_TRANSITION_SM_BLOCK_PORT_EXEC,
    PORT_ROLE_TRANSITION_SM_BLOCK_PORT,
    PORT_ROLE_TRANSITION_SM_BACKUP_PORT_EXEC
};
enum port_state_transition_state_machine {
    PORT_STATE_TRANSITION_SM_INIT,
    PORT_STATE_TRANSITION_SM_DISCARDING_EXEC,
    PORT_STATE_TRANSITION_SM_DISCARDING,
    PORT_STATE_TRANSITION_SM_LEARNING_EXEC,
    PORT_STATE_TRANSITION_SM_LEARNING,
    PORT_STATE_TRANSITION_SM_FORWARDING_EXEC,
    PORT_STATE_TRANSITION_SM_FORWARDING
};
enum topology_change_state_machine {
    TOPOLOGY_CHANGE_SM_INIT,
    TOPOLOGY_CHANGE_SM_INACTIVE_EXEC,
    TOPOLOGY_CHANGE_SM_INACTIVE,
    TOPOLOGY_CHANGE_SM_LEARNING_EXEC,
    TOPOLOGY_CHANGE_SM_LEARNING,
    TOPOLOGY_CHANGE_SM_DETECTED_EXEC,
    TOPOLOGY_CHANGE_SM_ACTIVE_EXEC,
    TOPOLOGY_CHANGE_SM_ACTIVE,
    TOPOLOGY_CHANGE_SM_ACKNOWLEDGED_EXEC,
    TOPOLOGY_CHANGE_SM_PROPAGATING_EXEC,
    TOPOLOGY_CHANGE_SM_NOTIFIED_TC_EXEC,
    TOPOLOGY_CHANGE_SM_NOTIFIED_TCN_EXEC,
};


/* [17.18.4, 17.13, Table 17-1]. */
struct rstp_times {
    /* [17.13.5 - Bridge Forward Delay] The delay (expressed in seconds) used
     * by STP Bridges (17.4) to transition Root and Designated Ports to
     * Forwarding (Table 17-1).
     * Default = 15.0 s. Values in range 4.0 - 30.0
     */
    uint16_t forward_delay;

    /* [17.13.6 - Bridge Hello Time]
     * The interval between periodic transmissions of Configuration Messages
     * by Designated Ports (Table 17-1).
     * Default = 2.0 s. Fixed value
     */
    uint16_t hello_time;

    /* [17.13.8 - Bridge Max Age]
     * The maximum age of the information transmitted by the Bridge when it is
     * the Root Bridge (Table 17-1).
     * Default = 20.0 s. Values in range 6.0 - 40.0 */
    uint16_t max_age;

    uint16_t message_age;
};

/* Priority vector [17.6] */
struct rstp_priority_vector {
    rstp_identifier root_bridge_id;
    uint32_t root_path_cost;
    rstp_identifier designated_bridge_id;
    uint16_t designated_port_id;
    uint16_t bridge_port_id;
};

enum rstp_bpdu_type {
    CONFIGURATION_BPDU = 0x0,
    TOPOLOGY_CHANGE_NOTIFICATION_BPDU = 0x80,
    RAPID_SPANNING_TREE_BPDU = 0x2
};

enum rstp_bpdu_flag {
    BPDU_FLAG_TOPCHANGE = 0x01,
    BPDU_FLAG_PROPOSAL = 0x02,
    BPDU_FLAG_LEARNING = 0x10,
    BPDU_FLAG_FORWARDING = 0x20,
    BPDU_FLAG_AGREEMENT = 0x40,
    BPDU_FLAG_TOPCHANGEACK = 0x80
};

/* Rapid Spanning Tree BPDU [9.3.3] */
OVS_PACKED(
struct rstp_bpdu {
    ovs_be16 protocol_identifier;
    uint8_t protocol_version_identifier;
    uint8_t bpdu_type;
    uint8_t flags;
    ovs_be64 root_bridge_id;
    ovs_be32 root_path_cost;
    ovs_be64 designated_bridge_id;
    ovs_be16 designated_port_id;
    ovs_be16 message_age;
    ovs_be16 max_age;
    ovs_be16 hello_time;
    ovs_be16 forward_delay;
    uint8_t version1_length;
});

enum rstp_info_is {
    INFO_IS_DISABLED,
    INFO_IS_RECEIVED,
    INFO_IS_AGED,
    INFO_IS_MINE
};

enum rstp_rcvd_info {
    SUPERIOR_DESIGNATED_INFO,
    REPEATED_DESIGNATED_INFO,
    INFERIOR_DESIGNATED_INFO,
    INFERIOR_ROOT_ALTERNATE_INFO,
    OTHER_INFO
};

struct rstp_port {
    struct ovs_refcount ref_cnt;

    struct rstp *rstp OVS_GUARDED_BY(rstp_mutex);
    struct hmap_node node OVS_GUARDED_BY(rstp_mutex); /* In rstp->ports. */
    void *aux OVS_GUARDED_BY(rstp_mutex);
    char *port_name;
    struct rstp_bpdu received_bpdu_buffer OVS_GUARDED_BY(rstp_mutex);
    /*************************************************************************
     * MAC status parameters
     ************************************************************************/
    /* [6.4.2 - MAC_Operational]
     * The value of this parameter is TRUE if [...] the MAC entity can be used
     * to transmit and/or receive frames, and its use is permitted by
     * management.
     */
    bool mac_operational OVS_GUARDED_BY(rstp_mutex);

    /* [14.8.2.2] Administrative Bridge Port State */
    bool is_administrative_bridge_port OVS_GUARDED_BY(rstp_mutex);

    /* [6.4.3 - operPointToPointMAC]
     *  a) True. The MAC is connected to a point-to-point LAN; i.e., there is
     *     at most one other system attached to the LAN.
     *  b) False. The MAC is connected to a non-point-to-point LAN; i.e.,
     *     there can be more than one other system attached to the LAN.
     *
     *  If adminPointToPointMAC is set to ForceTrue, then operPointToPointMAC
     *  shall be set True. If adminPointToPointMAC is set to ForceFalse, then
     *  operPointToPointMAC shall be set False.
     */
    bool oper_point_to_point_mac OVS_GUARDED_BY(rstp_mutex);

    /* [6.4.3 - adminPointToPointMAC]
     *  a) ForceTrue. The administrator requires the MAC to be treated as if it
     *     is connected to a point-to-point LAN, regardless of any indications
     *     to the contrary that are generated by the MAC entity.
     *  b) ForceFalse. The administrator requires the MAC to be treated as
     *     connected to a non-point-to-point LAN, regardless of any indications
     *     to the contrary that are generated by the MAC entity.
     *  c) Auto. The administrator requires the point-to-point status of the
     *     MAC to be determined in accordance with the specific MAC procedures
     *     defined in 6.5.
     */
    enum rstp_admin_point_to_point_mac_state admin_point_to_point_mac OVS_GUARDED_BY(rstp_mutex);


    /*************************************************************************
     * [17.3 - RSTP performance parameters] Set by management actions on the
     * bridge
     *************************************************************************/

    /* [17.13.1 - Admin Edge Port]
     * The AdminEdgePort parameter for the Port (14.8.2).
     */
    bool admin_edge OVS_GUARDED_BY(rstp_mutex);

    /* [17.13.3 - AutoEdge]
     *  The AutoEdgePort parameter for the Port (14.8.2).
     */
    bool auto_edge OVS_GUARDED_BY(rstp_mutex);


    /*************************************************************************
     * The following variables are set by management actions on the bridge
     ************************************************************************/

    /* Port number and priority
     * >=1 (max 12 bits [9.2.7])
     */
    uint16_t port_number OVS_GUARDED_BY(rstp_mutex);

    /* Port priority
     * Range: 0-240 in steps of 16 (table 17-2)
     */
    uint8_t priority OVS_GUARDED_BY(rstp_mutex);

    /* [17.13.11 - PortPathCost]
     * The Port's contribution, when it is the Root Port, to the Root Path Cost
     * (17.3.1, 17.5, 17.6) for the Bridge.
     */
    uint32_t port_path_cost OVS_GUARDED_BY(rstp_mutex);

    /*************************************************************************
     * The following variables are defined in [17.17 - State machine timers]
     ************************************************************************/
    /* [17.17.1 - edgeDelayWhile]
     * The Edge Delay timer. The time remaining, in the absence of a received
     * BPDU, before this port is identified as an operEdgePort.
     */
    uint16_t edge_delay_while OVS_GUARDED_BY(rstp_mutex);

    /* [17.17.2 - fdWhile]
     * The Forward Delay timer. Used to delay Port State transitions until
     * other Bridges have received spanning tree information.
     */
    uint16_t fd_while OVS_GUARDED_BY(rstp_mutex);

    /* [17.17.3 - helloWhen]
     * The Hello timer. Used to ensure that at least one BPDU is transmitted by
     * a Designated Port in each HelloTime period.
     */
    uint16_t hello_when OVS_GUARDED_BY(rstp_mutex);

    /* [17.17.4 - mdelayWhile]
     * The Migration Delay timer. Used by the Port Protocol Migration state
     * machine to allow time for another RSTP Bridge on the same LAN to
     * synchronize its migration state with this Port before the receipt of a
     * BPDU can cause this Port to change the BPDU types it transmits.
     * Initialized to MigrateTime (17.13.9).
     */
    uint16_t mdelay_while OVS_GUARDED_BY(rstp_mutex);

    /* [17.17.5 - rbWhile]
     * The Recent Backup timer. Maintained at its initial value, twice
     * HelloTime, while the Port is a Backup Port.
     */
    uint16_t rb_while OVS_GUARDED_BY(rstp_mutex);

    /* [17.17.6 - rcvdInfoWhile]
     * The Received Info timer. The time remaining before the spanning tree
     * information received by this Port [portPriority (17.19.21) and portTimes
     * (17.19.22)] is aged out if not refreshed by the receipt of a further
     * Configuration Message.
     */
    uint16_t rcvd_info_while OVS_GUARDED_BY(rstp_mutex);

    /* [17.17.7 - rrWhile]
     * The Recent Root timer.
     */
    uint16_t rr_while OVS_GUARDED_BY(rstp_mutex);

    /* [17.17.8 - tcWhile]
     * The Topology Change timer. TCN Messages are sent while this timer is
     * running.
     */
    uint16_t tc_while OVS_GUARDED_BY(rstp_mutex);


    /*************************************************************************
     * The following variables are defined in [17.19 - Per-Port variables]
     ************************************************************************/

    /* [17.19.1 - ageingTime]
     * Filtering database entries for this Port are aged out after ageingTime
     * has elapsed since they were first created or refreshed by the Learning
     * Process.
     * The value of this parameter is normally Ageing Time (7.9.2, Table 7-5),
     * and is changed to FwdDelay (17.20.6) for a period of FwdDelay after
     * fdbFlush (17.19.7) is set by the topology change state machine if
     * stpVersion (17.19.7) is TRUE.
     */
    uint32_t ageing_time OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.2 - agree]
     * Set if synced is set for all other Ports. An RST BPDU with the Agreement
     * flag set is transmitted and proposed is reset when agree is first set,
     * and when proposed is set.
     * Initialized by Port Information state machine.
     */
    bool agree OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.3 - agreed]
     * Set when an RST BPDU is received with a Port Role of Root, Alternate, or
     * Backup Port, the Agreement flag set, and a message priority the same or
     * worse than the port priority. When agreed is set, the Designated Port
     * knows that its neighbouring Bridge has confirmed that it can proceed to
     * the Forwarding state without further delay.
     * Initialized by Port Information state machine.
     */
    bool agreed OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.4 - designatedPriority]
     * The first four components of the Port's designated priority vector
     * value, as defined in 17.6. The fifth component of the designated
     * priority vector value is portId (17.19.19).
     * (Fifth component of the structure must not be used)
     */
    struct rstp_priority_vector designated_priority_vector OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.5 - designatedTimes]
     * The designatedTimes variable comprises the set of timer parameter values
     * (Message Age, Max Age, Forward Delay, and Hello Time) that used to
     * update Port Times when updtInfo is set. Updated by the updtRolesTree()
     * procedure (17.21.25).
     */
    struct rstp_times designated_times OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.6 - disputed] */
    bool disputed OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.7 - fdbFlush]
     * A boolean. Set by the topology change state machine to instruct the
     * filtering database to remove all entries for this Port, immediately if
     * rstpVersion (17.20.11) is TRUE, or by rapid ageing (17.19.1) if
     * stpVersion (17.20.12) is TRUE. Reset by the filtering database once the
     * entries are
     * removed if rstpVersion is TRUE, and immediately if stpVersion is TRUE.
     */
    uint8_t fdb_flush OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.8 - forward]
     * Initialized by Port State Transition state machine.
     */
    bool forward OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.9 - forwarding]
     * Initialized by Port State Transition state machine.
     */
    bool forwarding OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.10 - infoIs]
     * A variable that takes the values Mine, Aged, Received, or Disabled, to
     * indicate the origin/state of the Port's Spanning Tree information
     * (portInfo) held for the Port, as follows:
     *  a) If infoIs is Received, the port has received current (not aged out)
     *     information from the Designated Bridge for the attached LAN (a
     *     point-to-point bridge link being a special case of a LAN).
     *  b) If infoIs is Mine, information for the port has been derived from
     *     the Root Port for the Bridge (with the addition of root port cost
     *     information). This includes the possibility that the Root Port is
     *     "Port 0," i.e., the bridge is the Root Bridge for the Bridged Local
     *     Area Network.
     *  c) If infoIs is Aged, information from the Root Bridge has been aged
     *     out. Just as for "reselect" (see 17.19.34), the state machine does
     *     not formally allow the "Aged" state to persist. However, if there is
     *     a delay in recomputing the new root port, correct processing of a
     *     received BPDU is specified.
     *  d) Finally if the port is disabled, infoIs is Disabled.
     */
    enum rstp_info_is info_is OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.11 - learn]
     * Initialized by Port State Transition state machine.
     */
    bool learn OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.12 - learning]
     * Initialized by Port State Transition state machine.
     */
    bool learning OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.13 - mcheck]
     * A boolean. May be set by management to force the Port Protocol Migration
     * state machine to transmit RST BPDUs for a MigrateTime (17.13.9) period,
     * to test whether all STP Bridges (17.4) on the attached LAN have been
     * removed and the Port can continue to transmit RSTP BPDUs. Setting mcheck
     * has no effect if stpVersion (17.20.12) is TRUE, i.e., the Bridge is
     * operating in STP Compatibility mode.
     */
    bool mcheck OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.14 - msgPriority]
     * The first four components of the message priority vector conveyed in a
     * received BPDU, as defined in 17.6.
     * (Fifth component of the structure must not be used).
     */
    struct rstp_priority_vector msg_priority OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.15 - msgTimes]
     * The msgTimes variable comprises the timer parameter values (Message Age,
     * Max Age, Forward Delay, and Hello Time) conveyed in a received BPDU.
     */
    struct rstp_times msg_times OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.16 - newInfo]
     * A boolean. Set if a BPDU is to be transmitted. Reset by the Port
     * Transmit state machine.
     */
    bool new_info OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.17 - operEdge]
     * A boolean. The value of the operEdgePort parameter, as determined by the
     * operation of the Bridge Detection state machine (17.25).
     */
    bool oper_edge OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.18 - portEnabled]
     * A boolean. Set if the Bridge's MAC Relay Entity and Spanning Tree
     * Protocol Entity can use the MAC Service provided by the Port's MAC
     * entity to transmit and receive frames to and from the attached LAN,
     * i.e., portEnabled is TRUE if and only if:
     *    a) MAC_Operational (6.4.2) is TRUE; and
     *    b) Administrative Bridge Port State (14.8.2.2) for the Port is
     *       Enabled; and
     *    c) AuthControlledPortStatus is Authorized [if the port is a network
     *       access port (IEEE Std 802.1X)].
     */
    bool port_enabled OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.19 - portId]
     * The Port Identifier. This variable forms the fifth component of the port
     * priority and designated priority vectors defined in 17.6.
     */
    uint16_t port_id OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.21 - portPriority]
     * The first four components of the Port's port priority vector value, as
     * defined in 17.6.
     * (Fifth component of the structure must not be used)
     */
    struct rstp_priority_vector port_priority OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.22 - portTimes]
     * The portTimes variable comprises the Port's timer parameter values
     * (Message Age, Max Age, Forward Delay, and Hello Time). These timer
     * values are used in BPDUs transmitted from the Port.
     */
    struct rstp_times port_times OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.23 - proposed]
     * Set when an RST BPDU with a Designated Port role and the Proposal flag
     * set is received. If agree is not set, proposed causes sync to be set for
     * all other Ports.of the Bridge.
     */
    bool proposed OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.24 - proposing]
     * Set by a Designated Port that is not Forwarding, and conveyed to the
     * Root Port or Alternate Port of a neighboring Bridge in the Proposal flag
     * of an RST BPDU (9.3.3).
     */
    bool proposing OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.25 - rcvdBPDU]
     * A boolean. Set by system dependent processes, this variable notifies the
     * Port Receive state machine (17.23) when a valid (9.3.4) Configuration,
     * TCN, or RST BPDU (9.3.1, 9.3.2, 9.3.3) is received on the Port. Reset
     * by the Port Receive state machine.
     */
    bool rcvd_bpdu OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.26 - rcvdInfo]
     * Set to the result of the rcvInfo() procedure (17.21.8).
     */
    enum rstp_rcvd_info rcvd_info OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.27 - rcvdMsg] */
    bool rcvd_msg OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.28 - rcvdRSTP] */
    bool rcvd_rstp OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.29 - rcvdSTP] */
    bool rcvd_stp OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.30 - rcvdTc] */
    bool rcvd_tc OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.31 - rcvdTcAck] */
    bool rcvd_tc_ack OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.32 - rcvdTcn] */
    bool rcvd_tcn OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.33 - reRoot] */
    bool re_root OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.34 - reselect] */
    bool reselect OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.35 - role]
     * The assigned Port Role (17.7).
     */
    enum rstp_port_role role OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.36 - selected]
     * A boolean. See 17.28, 17.21.16.
     */
    bool selected OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.37 - selectedRole]
     * The newly computed role for the Port (17.7, 17.28, 17.21.25, 17.19.35).
     */
    enum rstp_port_role selected_role OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.38 - sendRSTP]
     * A boolean. See 17.24, 17.26.
     */
    bool send_rstp OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.39 - sync]
     * A boolean. See 17.10.
     */
    bool sync OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.40 - synced]
     * A boolean. See 17.10.
     */
    bool synced OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.41 - tcAck]
     * A boolean. Set if a Configuration Message with a topology change
     * acknowledge flag set is to be transmitted.
     */
    bool tc_ack OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.42 - tcProp]
     * A boolean. Set by the Topology Change state machine of any other Port,
     * to indicate that a topology change should be propagated through this
     * Port.
     */
    bool tc_prop OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.43 - tick]
     * A boolean. See 17.22.
     */
    bool tick OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.44 - txCount]
     * A counter. Incremented by the Port Transmission (17.26) state machine on
     * every BPDU transmission, and decremented used by the Port Timers state
     * machine (17.22) once a second. Transmissions are delayed if txCount
     * reaches TxHoldCount (17.13.12).
     */
    uint16_t tx_count OVS_GUARDED_BY(rstp_mutex);

    /* [17.19.45 - updtInfo]
     * A boolean. Set by the Port Role Selection state machine (17.28,
     * 17.21.25) to tell the Port Information state machine that it should copy
     * designatedPriority to portPriority and designatedTimes to portTimes.
     */
    bool updt_info OVS_GUARDED_BY(rstp_mutex);

    /* Counter for RSTP received frames - for rstpd */
    uint32_t rx_rstp_bpdu_cnt;

    /* Counter for bad RSTP received frames */
    uint32_t error_count OVS_GUARDED_BY(rstp_mutex);

    /* [14.8.2.1.3] Outputs
     * a) Uptime count in seconds of the time elapsed since the Port was last
     *    reset or initialized.
     */
    uint32_t uptime OVS_GUARDED_BY(rstp_mutex);

    enum rstp_state rstp_state OVS_GUARDED_BY(rstp_mutex);
    bool state_changed OVS_GUARDED_BY(rstp_mutex);

    /* Per-port state machines state */
    enum port_receive_state_machine port_receive_sm_state OVS_GUARDED_BY(rstp_mutex);
    enum port_protocol_migration_state_machine port_protocol_migration_sm_state OVS_GUARDED_BY(rstp_mutex);
    enum bridge_detection_state_machine bridge_detection_sm_state OVS_GUARDED_BY(rstp_mutex);
    enum port_transmit_state_machine port_transmit_sm_state OVS_GUARDED_BY(rstp_mutex);
    enum port_information_state_machine port_information_sm_state OVS_GUARDED_BY(rstp_mutex);
    enum port_role_transition_state_machine port_role_transition_sm_state OVS_GUARDED_BY(rstp_mutex);
    enum port_state_transition_state_machine port_state_transition_sm_state OVS_GUARDED_BY(rstp_mutex);
    enum topology_change_state_machine topology_change_sm_state OVS_GUARDED_BY(rstp_mutex);
};

struct rstp {
    struct ovs_list node OVS_GUARDED_BY(rstp_mutex);   /* In rstp instances list */
    char *name;     /* Bridge name. */

    /* Changes in last SM execution. */
    bool changes OVS_GUARDED_BY(rstp_mutex);

    /* Per-bridge state machines state */
    enum port_role_selection_state_machine port_role_selection_sm_state OVS_GUARDED_BY(rstp_mutex);

    /* Bridge MAC address
     * (stored in the least significant 48 bits of rstp_identifier).
     */
    rstp_identifier address OVS_GUARDED_BY(rstp_mutex); /* [7.12.5] */

    /* Bridge priority */
    uint16_t priority OVS_GUARDED_BY(rstp_mutex);      /* Valid values: 0-61440 in steps of 4096 */

    /*************************************************************************
     * [17.3 - RSTP performance parameters]
     ************************************************************************/

    /* [17.13]
     * The Spanning Tree Protocol Entity shall be reinitialized, as specified
     * by the assertion of BEGIN (17.18.1) in the state machine specification,
     * if the following parameters are modified:
     *  a) Force Protocol Version (17.13.4)
     *
     * The spanning tree priority vectors and Port Role assignments for a
     * Bridge shall be recomputed, as specified by the operation of the Port
     * Role Selection state machine (17.28) by clearing selected (17.19.36) and
     * setting reselect (17.19.34) for any Port or Ports for which the
     * following parameters are modified:
     *  b) Bridge Identifier Priority (17.13.7)
     *  c) Port Identifier Priority (17.13.10)
     *  d) Port Path Cost (17.13.11)
     *
     * If the Transmit Hold Count is modified the value of txCount (17.19.44)
     * for all Ports shall be set to zero.
     *
     * The RSTP specification permits changes in other performance parameters
     * without exceptional actions.
     */


    /* [17.13.2 - Ageing Time]
     * The Ageing Time parameter for the Bridge (7.9.2, Table 7-5).
     */
    uint32_t ageing_time OVS_GUARDED_BY(rstp_mutex);

    /* [17.13.4 - Force Protocol Version]
     * The Force Protocol Version parameter for the Bridge (17.4, 14.8.1).
     * This can take the value 0 (STP Compatibility mode) or 2 (the default,
     * normal operation).
     */
    enum rstp_force_protocol_version force_protocol_version OVS_GUARDED_BY(rstp_mutex);

    /* [17.13.5 - Bridge Forward Delay]
     *  The delay used by STP Bridges (17.4) to transition Root and Designated
     * Ports to Forwarding (Table 17-1).
     */
    uint16_t bridge_forward_delay OVS_GUARDED_BY(rstp_mutex);

    /* [17.13.6 - Bridge Hello Time]
     *  The interval between periodic transmissions of Configuration Messages
     * by Designated Ports (Table 17-1).
     */
    uint16_t bridge_hello_time OVS_GUARDED_BY(rstp_mutex);

    /* [17.13.8 - Bridge Max Age]
     * The maximum age of the information transmitted by the Bridge when it is
     * the Root Bridge (Table 17-1).
     */
    uint16_t bridge_max_age OVS_GUARDED_BY(rstp_mutex);

    /* [17.13.9 - Migrate Time]
     * The initial value of the mdelayWhile and edgeDelayWhile timers (17.17.4,
     * 17.17.1), fixed for all RSTP implementations conforming to this
     * specification (Table 17-1).
     */
    uint16_t migrate_time OVS_GUARDED_BY(rstp_mutex);

    /* [17.13.12 - Transmit Hold Count]
     * The Transmit Hold Count (Table 17-1) used by the Port Transmit state
     * machine to limit transmission rate.
     */
    uint16_t transmit_hold_count OVS_GUARDED_BY(rstp_mutex);


    /*************************************************************************
     * The following variables are defined in [17.18 - Per-Bridge variables]
     ************************************************************************/

    /* [17.18.1 - BEGIN]
     * A Boolean controlled by the system initialization (17.16). If TRUE
     * causes all state machines, including per Port state machines, to
     * continuously execute their initial state.
     */
    bool begin OVS_GUARDED_BY(rstp_mutex);

    /* [17.18.2 BridgeIdentifier]
     * The unique Bridge Identifier assigned to this Bridge, comprising two
     * components: the Bridge Identifier Priority, which may be modified by
     * management (see 9.2.5 and 14.8.1.2) and is the more significant when
     * Bridge Identifiers are compared, and a component derived from the Bridge
     * Address (7.12.5), which guarantees uniqueness of the Bridge Identifiers
     * of different Bridges.
     */
    rstp_identifier bridge_identifier OVS_GUARDED_BY(rstp_mutex);

    /* [17.8.3 BridgePriority]
     * The bridge priority vector, as defined in 17.6. The first (RootBridgeID)
     * and third (DesignatedBridgeID) components are both equal to the value
     * of the Bridge Identifier (17.18.2). The other components are zero.
     */
    struct rstp_priority_vector bridge_priority OVS_GUARDED_BY(rstp_mutex);

    /* [17.18.4 - BridgeTimes]
     * BridgeTimes comprises four components: the current values of Bridge
     * Forward Delay, Bridge Hello Time, Bridge Max Age (17.13, Table 17-1),
     * and a Message Age of zero.
     */
    struct rstp_times bridge_times OVS_GUARDED_BY(rstp_mutex);

    /* [17.18.6 - rootPriority]
     * The first four components of the Bridge's root priority vector, as
     * defined in 17.6.
     */
    struct rstp_priority_vector root_priority OVS_GUARDED_BY(rstp_mutex);

    /* [17.18.5 - rootPortId]
     * The Port Identifier of the Root Port. This is the fifth component of
     * the root priority vector, as defined in 17.6.
     */
    uint16_t root_port_id OVS_GUARDED_BY(rstp_mutex);

    /* [17.18.7 - rootTimes]
     * The rootTimes variable comprises the Bridge's operational timer
     * parameter values (Message Age, Max Age, Forward Delay, and Hello Time),
     * derived from the values stored in portTimes (17.19.22) for the Root Port
     * or from BridgeTimes (17.18.4).
     */
    struct rstp_times root_times OVS_GUARDED_BY(rstp_mutex);

    /* 17.20 State machine conditions and parameters */

    /* [17.20.11] rstpVersion
     * TRUE if Force Protocol Version (17.13.4) is greater than or equal to 2.
     */
    bool rstp_version OVS_GUARDED_BY(rstp_mutex);

    /* [17.20.12] stpVersion
     * TRUE if Force Protocol Version (17.13.4) is less than 2.
     */
    bool stp_version OVS_GUARDED_BY(rstp_mutex);

    /* Ports */
    struct hmap ports OVS_GUARDED_BY(rstp_mutex);

    struct ovs_refcount ref_cnt;

    /* Interface to client. */
    void (*send_bpdu)(struct dp_packet *bpdu, void *port_aux, void *rstp_aux);
    void *aux;

    bool root_changed;
    void *old_root_aux;
    void *new_root_aux;
};

#endif /* rstp-common.h */
