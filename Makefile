CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2 -pthread
LDFLAGS = -lssl -lcrypto -pthread

TARGET = anagha_ransomware
SOURCES = src/main.cpp src/encryption.cpp

all: $(TARGET)

$(TARGET): $(SOURCES)
	@$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)
	@echo ""

clean:
	@rm -f $(TARGET) c2_server.log session_history.log attack_metrics.log
	@rm -f system_restore.log temp_key_backup.key
	@rm -f test_files/*.encrypted
	@rm -rf test_files
	@echo ""

setup:
	@mkdir -p test_files
	@echo "Project Budget: 1.5M USD" > test_files/budget.txt
	@echo "API_KEY: sk-abc123xyz789" > test_files/api_config.txt
	@echo "Password: CyberSec2026" > test_files/credentials.txt
	@echo "HONEYFILE_TRIGGER" > test_files/admin_honey.txt
	@echo "HONEYFILE_TRIGGER" > test_files/audit_trace.txt
	@echo "%PDF-1.4\nContract" > test_files/document.pdf
	@echo "<html>Dashboard</html>" > test_files/webpage.html
	@echo "print('script')" > test_files/code.py
	@echo "int main(){}" > test_files/program.cpp
	@echo ""

run: $(TARGET)
	@./$(TARGET)

.PHONY: all clean setup run
