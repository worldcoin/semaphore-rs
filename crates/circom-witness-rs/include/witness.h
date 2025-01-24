#pragma once
#include "rust/cxx.h"
#include <memory>

typedef unsigned long long u64;
typedef uint32_t u32;
typedef uint8_t u8;

struct Circom_CalcWit;

void run(Circom_CalcWit *buf);
uint get_size_of_io_map();
uint get_total_signal_no();
uint get_main_input_signal_no();
uint get_main_input_signal_start();
uint get_number_of_components();
uint get_size_of_constants();
uint get_size_of_input_hashmap();
uint get_size_of_witness();
