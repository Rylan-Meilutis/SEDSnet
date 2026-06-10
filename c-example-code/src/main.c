#include "telemetry.h"
#include "sedsnet_c_wrapper.h"
#include <unistd.h>

int main(void) {
  SedsResult result = init_telemetry_router();
  if (result != SEDS_OK) {
    return (int)print_telemetry_error(result);
  }

  SedsTypeRef gps_data;
  SedsTypeRef message_data;
  result = seds_type_ref_by_name(SEDS_NAME_LITERAL("GPS_DATA"), &gps_data);
  if (result != SEDS_OK) {
    return (int)print_telemetry_error(result);
  }
  result = seds_type_ref_by_name(SEDS_NAME_LITERAL("MESSAGE_DATA"), &message_data);
  if (result != SEDS_OK) {
    return (int)print_telemetry_error(result);
  }

  const float gps[3] = {37.7749f, -122.4194f, 30.0f};
  result = log_telemetry_synchronous(gps_data, gps, 3, sizeof(gps[0]));
  if (result != SEDS_OK) {
    print_telemetry_error(result);
  }

  usleep(1000);

  result = log_telemetry_asynchronous(gps_data, gps, 3, sizeof(gps[0]));
  if (result != SEDS_OK) {
    print_telemetry_error(result);
  }

  result = log_telemetry_string_asynchronous(message_data, "hello from the async queue");
  if (result != SEDS_OK) {
    print_telemetry_error(result);
  }

  result = telemetry_periodic(20);
  if (result != SEDS_OK) {
    print_telemetry_error(result);
  }

  return 0;
}
