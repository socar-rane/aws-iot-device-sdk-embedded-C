#ifndef DATA_STRUCT_H
#define DATA_STRUCT_H

/* C standard includes. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>

enum {
    STS_CLEAR,
    STS_UPDATE,
    STS_REPORT
};

typedef struct {
    uint8_t fl;
    uint8_t fr;
    uint8_t rl;
    uint8_t rr;
    uint8_t trunk;
    uint8_t etc_gate;
} door_state;

typedef struct {
    uint8_t fl;
    uint8_t fr;
    uint8_t rl;
    uint8_t rr;
} door_lock;

typedef struct {
    door_state ds;
    door_lock dl;
    uint8_t engine;
    uint8_t light;
    uint8_t payment_card;
    uint8_t gear_pos;
    uint8_t gear_step;
    uint8_t battery_volt;
    int odometer;
    uint8_t fuel_percent;
    uint8_t fuel_level;
    uint8_t power_module;
} sts_status_t;

typedef struct {
    uint16_t distance;
    uint32_t odometer;
    uint16_t drive_time;
    uint8_t fuel_percent;
    uint8_t fuel_level;
    uint8_t fuel_cosumption;
    uint8_t battery_volt;
    uint8_t internal_battery_volt;
} trip_t;

#endif