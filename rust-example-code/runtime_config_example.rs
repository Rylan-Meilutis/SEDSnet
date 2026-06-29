use sedsnet::config::{
    DataEndpoint, RuntimeMemoryConfig, runtime_tuning_config, set_runtime_device_identifier,
    set_runtime_tuning_config,
};
use sedsnet::relay::{Relay, RelayConfig};
use sedsnet::router::{AddressAssignmentMode, EndpointHandler, Router, RouterConfig};
use sedsnet::timesync::{TimeSyncConfig, TimeSyncRole};
use sedsnet::TelemetryResult;

fn main() -> TelemetryResult<()> {
    // Process-wide defaults used by packet helpers and newly-created time-sync trackers.
    set_runtime_device_identifier("GROUND_STATION")?;

    let mut tuning = runtime_tuning_config();
    tuning.payload_compress_threshold = 24;
    tuning.static_string_length = 512;
    tuning.static_hex_length = 512;
    tuning.string_precision = 6;
    tuning.max_handler_retries = 4;
    tuning.reliable_retransmit_ms = 300;
    tuning.reliable_max_retries = 10;
    tuning.reliable_max_pending = 96;
    tuning.reliable_max_return_routes = 96;
    tuning.reliable_max_end_to_end_pending = 96;
    tuning.reliable_max_end_to_end_ack_cache = 256;
    set_runtime_tuning_config(tuning)?;

    // Per-router/relay queue-owned memory budget. RX, TX, reliable buffers, recent IDs,
    // schema/discovery state, and network-variable caches all draw from this budget.
    let memory = RuntimeMemoryConfig::new(
        65_536, // shared queue budget
        256,    // recent packet IDs
        512,    // starting queue allocation
        2.0,    // growth step
    )?;

    let handler = EndpointHandler::new_packet_handler(DataEndpoint::named("RADIO"), |pkt| {
        println!("[RADIO] {pkt}");
        Ok(())
    });

    let router_cfg = RouterConfig::new([handler])
        .with_hostname("FC26_MAIN")
        .with_static_address(0x1020_3040)
        .with_timesync(TimeSyncConfig {
            role: TimeSyncRole::Auto,
            priority: 100,
            ..TimeSyncConfig::default()
        })
        .with_memory_config(memory)?;
    let router = Router::new(router_cfg);

    // Runtime changes after construction.
    router.set_timesync_config(Some(TimeSyncConfig {
        role: TimeSyncRole::Source,
        priority: 10,
        ..TimeSyncConfig::default()
    }));
    router.set_address_assignment(AddressAssignmentMode::Requested(0x1020_3041))?;

    let relay_cfg = RelayConfig::default()
        .with_sender("RF_RELAY")
        .with_memory_config(memory)?;
    let relay = Relay::new_with_config(relay_cfg, Box::new(|| 0));

    println!("{}", router.export_memory_layout_json());
    println!("{}", relay.export_memory_layout_json());
    Ok(())
}
