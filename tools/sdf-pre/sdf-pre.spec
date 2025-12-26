%global debug_package %{nil}
Name:           sdf-pre
Version:        1.0.0
Release:        1%{?dist}
Summary:        sdf utils when machine Restart
License:        GPLv3+

# Modified to use a single tarball
Source0:        %{name}-%{version}.tar.gz

# Dependency checks
Requires:       systemd
Requires:       coreutils
Requires:       procps-ng
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units

%description
This package provides a systemd service for loading TEE drivers and maintaining
the teecd process. It automatically loads tzdriver.ko and tee_upgrade.ko kernel
modules and ensures the teecd process is always running.

%prep
# Simplified extraction
%setup -q

%build
# No compilation step needed
echo "No compilation needed for this package."

%install
# Clean build root
rm -rf %{buildroot}

# Create necessary directories
install -d -m 0755 %{buildroot}%{_bindir}
install -d -m 0755 %{buildroot}%{_unitdir}
install -d -m 0755 %{buildroot}/var/log
install -d -m 0755 %{buildroot}/var/run

# Install files from BUILD directory
# Note: %{_builddir}/%{name}-%{version} is the extracted directory
install -m 0755 %{_builddir}/%{name}-%{version}/sdf-pre.sh %{buildroot}%{_bindir}/sdf-pre.sh
install -m 0644 %{_builddir}/%{name}-%{version}/sdf-pre.service %{buildroot}%{_unitdir}/sdf-pre.service
# Install README.md to documentation directory
install -d -m 0755 %{buildroot}%{_docdir}
install -m 0644 %{_builddir}/%{name}-%{version}/README.md %{buildroot}%{_docdir}/README.md

%pre
# Execute before RPM installation
# Check if kernel modules exist
KERNEL_VERSION=$(uname -r)
DRIVER_PATH="/lib/modules/$KERNEL_VERSION/kernel/drivers/trustzone"

if [ ! -d "$DRIVER_PATH" ]; then
    echo "Warning: Driver path does not exist: $DRIVER_PATH"
    echo "Please ensure TEE drivers are properly installed"
fi

%post
# Execute after RPM installation
# Reload systemd configuration
systemctl daemon-reload
systemctl enable sdf-pre.service
systemctl start sdf-pre.service

%preun
# Execute before RPM uninstallation
%systemd_preun sdf-pre.service

%postun
# Execute after RPM uninstallation
%systemd_postun_with_restart sdf-pre.service

%clean
rm -rf %{buildroot}

%files
# Define files in the package
%defattr(-,root,root,-)
%doc %{_docdir}/README.md
%attr(755,root,root) %{_bindir}/sdf-pre.sh
%config(noreplace) %{_unitdir}/sdf-pre.service

%changelog
* Fri Dec 12 2025 Xiangchao <xiangchao15@huawei.com> 1.0.0-1
- Initial release of sdf-pre