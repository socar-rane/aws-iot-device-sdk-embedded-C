DEMO := jobs_demo_mosquitto
JOBS_DIR := ../../../libraries/aws/jobs-for-aws-iot-embedded-sdk/source
JSON_DIR := ../../../libraries/standard/coreJSON/source
CAR_DATA_DIR := ../../../demos/jobs/jobs_demo_mosquitto
INCLUDES := -I. -I$(JOBS_DIR)/include -I$(JSON_DIR)/include
CFLAGS := -Wall -Wextra -Wpedantic -Wno-unused-parameter $(INCLUDES)
LDLIBS := -lmosquitto -lrt
CC := gcc

$(DEMO): $(DEMO).o jobs.o core_json.o

jobs.o: $(JOBS_DIR)/jobs.c
	$(CC) $(CFLAGS) $< -c -o $@

core_json.o: $(JSON_DIR)/core_json.c
	$(CC) $(CFLAGS) $< -c -o $@

clean:
	rm -fr $(DEMO) *.o

.PHONY: clean
