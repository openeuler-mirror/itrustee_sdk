#!/bin/bash
# sdf-pre service script
# description：
# 1. insmod tzriver.ko
# 2. run teecd
# 3. insmod tee_upgrade.ko
# 4. run teecd(insmod tee_upgrade.ko will kill teecd process)
# 5. regularly monitor and keep alive

set -e

KERNEL_VERSION=$(uname -r)
DRIVERS_DIR="/lib/modules/${KERNEL_VERSION}/kernel/drivers/trustzone"
LOG_FILE="/var/log/tee-env-pre.log"
CHECK_INTERVAL=30  # check interval(seconds)

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}


# Check and insmod modules
load_kernel_modules_and_teecd() {
    log_message "Start to install modules..."
    
    if [ ! -d "$DRIVERS_DIR" ]; then
        log_message "ERROR: $DRIVERS_DIR does not exist!"
        return 1
    fi
    
    local modules=("tzdriver" "tee_upgrade")
    for module in "${modules[@]}"; do
        load_single_module "$module"
        if [ $? -ne 0 ]; then
            return 1
        fi
        start_teecd
        if [ $? -ne 0 ]; then
            return 1
        fi
    done
    
    log_message "all modules are installed."
    return 0
}

load_single_module() {
    local module_name="$1"
    local module_file="${DRIVERS_DIR}/${module_name}.ko"
    
    if [ ! -f "$module_file" ]; then
        log_message "ERROR: ${module_file} does not exist!"
        return 1
    fi

    if lsmod | grep -q "^${module_name}\b"; then
        log_message "${module_name} is already installed."
        return 0
    fi
    
    log_message "Installing ${module_name}.ko..."
    if insmod "$module_file" 2>> "$LOG_FILE"; then
        log_message "Successfully install ${module_name}.ko"
        return 0
    else
        log_message "ERROR: Fail to install ${module_name}.ko"
        return 1
    fi
}

start_teecd() {
    log_message "Running teecd..."
    
    if [ ! -x "/usr/bin/teecd" ]; then
        log_message "ERROR: /usr/bin/teecd does not exist or is not executable"
        return 1
    fi

    if ! pgrep -x teecd > /dev/null; then
        nohup /usr/bin/teecd > /dev/null 2>&1 &
        sleep 2
        if pgrep -x teecd > /dev/null; then
            log_message "Successfully run teecd!"
        else
            log_message "ERROR: Fail to run teecd"
            return 1
        fi
    else
        log_message "teecd is already running"
    fi
    return 0
}


check_processes() {
    local all_ok=0
    
    if ! lsmod | grep -q tzdriver; then
        log_message "tzdriver.ko is not installed"
        all_ok=1
    fi
    
    if ! lsmod | grep -q tee_upgrade; then
        log_message "tee_upgrade.ko is not installed"
        all_ok=1
    fi
    
    if ! pgrep -x "teecd" > /dev/null; then
        log_message "teecd is not running"
        all_ok=1
    fi
    
    return $all_ok
}

monitor_loop() {
    log_message "Monitoring..."
    
    while true; do
        if ! check_processes; then
            log_message "Detected abnormal termination of processes, try to restart..."
            
            load_kernel_modules_and_teecd
            
            if check_processes; then
                log_message "Process recovery successful"
            else
                log_message "Process recovery failed"
            fi
        fi

        sleep $CHECK_INTERVAL
    done
}


main() {
    log_message "========== start sdf-pre service =========="
    
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 755 "$LOG_FILE"

    load_kernel_modules_and_teecd
    monitor_loop
}

main 