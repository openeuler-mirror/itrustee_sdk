#!/bin/bash
# build-rpm.sh 

set -e

PACKAGE_NAME="sdf-pre"
VERSION="1.0.0"
RELEASE="1"
SPEC_FILE="${PACKAGE_NAME}.spec"
SOURCE_DIR="rpm-sources"
BUILD_ROOT="${HOME}/rpmbuild"
SCRIPT_FILE="sdf-pre.sh"
SERVICE_FILE="sdf-pre.service"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    print_message "Checking build dependencies..."
    
    local missing_deps=()
    
    for cmd in rpm rpmbuild tar gzip; do
        if ! command -v $cmd &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        print_error "Missing required tools: ${missing_deps[*]}"
        print_message "Please install: sudo yum install rpm-build rpmdevtools"
        exit 1
    fi
    
    if [ ! -d "$BUILD_ROOT" ]; then
        print_message "Initializing rpmbuild directory structure..."
        rpmdev-setuptree
    fi
}

prepare_sources() {
    print_message "Preparing source code..."
    
    TEMP_DIR=$(mktemp -d)
    
    cp "$SCRIPT_FILE" "$TEMP_DIR/"
    cp "$SERVICE_FILE" "$TEMP_DIR/"
    cp "README.md" "$TEMP_DIR/"
    
    # Create tarball
    tar czf "${BUILD_ROOT}/SOURCES/${PACKAGE_NAME}-${VERSION}.tar.gz" \
        -C "$TEMP_DIR" \
        --transform "s,^,${PACKAGE_NAME}-${VERSION}/," \
        .
    
    rm -rf "$TEMP_DIR"
    cp "$SPEC_FILE" "${BUILD_ROOT}/SPECS/"
}

build_rpm() {
    print_message "Building RPM package..."
    
    cd "${BUILD_ROOT}/SPECS"
    
    # Build RPM
    rpmbuild -ba \
        --define "_topdir ${BUILD_ROOT}" \
        --define "_version ${VERSION}" \
        --define "_release ${RELEASE}" \
        "${SPEC_FILE}"
    
    if [ $? -eq 0 ]; then
        print_message "RPM build successful!"
        
        # Display built RPM files
        echo -e "\n${GREEN}Built RPM packages:${NC}"
        find "${BUILD_ROOT}/RPMS" -name "*.rpm" -type f
        find "${BUILD_ROOT}/SRPMS" -name "*.rpm" -type f
    else
        print_error "RPM build failed!"
        exit 1
    fi
}

clean_old_builds() {
    print_message "Cleaning old build files..."
    
    # Clean RPM build directories
    rm -rf "${BUILD_ROOT}/BUILD/${PACKAGE_NAME}-${VERSION}"
    rm -rf "${BUILD_ROOT}/BUILDROOT/${PACKAGE_NAME}-${VERSION}-${RELEASE}.*"
    
    # Clean old RPM packages
    rm -f "${BUILD_ROOT}/RPMS"/noarch/"${PACKAGE_NAME}"*.rpm
    rm -f "${BUILD_ROOT}/SRPMS"/"${PACKAGE_NAME}"*.rpm
}

verify_rpm() {
    print_message "Verifying RPM package..."
    
    local rpm_file=$(find "${BUILD_ROOT}/RPMS" -name "${PACKAGE_NAME}*.rpm" -type f | head -1)
    
    if [ -f "$rpm_file" ]; then
        echo -e "\n${GREEN}RPM package info:${NC}"
        rpm -qpi "$rpm_file"
        
        echo -e "\n${GREEN}RPM package file list:${NC}"
        rpm -qpl "$rpm_file"
    else
        print_error "No RPM package file found"
    fi
}

install_test() {
    read -p "Install and test the RPM package? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        local rpm_file=$(find "${BUILD_ROOT}/RPMS" -name "${PACKAGE_NAME}*.rpm" -type f | head -1)
        
        if [ -f "$rpm_file" ]; then
            print_message "Installing RPM package..."
            sudo rpm -ivh "$rpm_file"
            
            print_message "Starting service..."
            sudo systemctl daemon-reload
            sudo systemctl start sdf-pre.service
            sudo systemctl status sdf-pre.service
        fi
    fi
}

main() {
    print_message "Starting ${PACKAGE_NAME} RPM build process..."
    
    check_dependencies
    clean_old_builds
    prepare_sources
    build_rpm
    verify_rpm

    install_test
    
    print_message "Complete!"
}

main