use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use sedsnet::config::{DataEndpoint, DataType};
use sedsnet::packet::Packet;
use sedsnet::wire_format::{pack_packet, peek_frame_info, unpack_packet};
use std::hint::black_box;

const GPS_VALUES: &[f32] = &[37.7749_f32, -122.4194_f32, 30.0_f32];
const MESSAGE_TEXT: &str = "criterion benchmark packet payload";
const TIMESTAMP_MS: u64 = 1_741_017_600_000;

fn endpoints() -> [DataEndpoint; 2] {
    [DataEndpoint::named("RADIO"), DataEndpoint::named("SD_CARD")]
}

fn gps_packet() -> Packet {
    Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        GPS_VALUES,
        &endpoints(),
        TIMESTAMP_MS,
    )
    .unwrap()
}

fn message_packet() -> Packet {
    Packet::from_str_slice(
        DataType::named("MESSAGE_DATA"),
        MESSAGE_TEXT,
        &endpoints(),
        TIMESTAMP_MS,
    )
    .unwrap()
}

fn benchmark_packet_paths(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_paths");

    group.bench_function("construct_gps_packet", |b| {
        b.iter(|| {
            black_box(
                Packet::from_f32_slice(
                    DataType::named("GPS_DATA"),
                    black_box(GPS_VALUES),
                    black_box(&endpoints()),
                    black_box(TIMESTAMP_MS),
                )
                .unwrap(),
            )
        });
    });

    let gps_packet = gps_packet();
    let packed_gps = pack_packet(&gps_packet);

    group.bench_function("pack_gps_packet", |b| {
        b.iter(|| black_box(pack_packet(black_box(&gps_packet))));
    });

    group.bench_function("unpack_gps_packet", |b| {
        b.iter(|| black_box(unpack_packet(black_box(&packed_gps))).unwrap());
    });

    let message_packet = message_packet();

    group.bench_function("roundtrip_message_packet", |b| {
        b.iter_batched(
            || pack_packet(&message_packet),
            |wire| black_box(unpack_packet(black_box(&wire))).unwrap(),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("peek_gps_frame_info", |b| {
        b.iter(|| black_box(peek_frame_info(black_box(&packed_gps))).unwrap());
    });

    group.finish();
}

criterion_group!(benches, benchmark_packet_paths);
criterion_main!(benches);
