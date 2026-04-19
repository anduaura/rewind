Name:           rewind
Version:        %{version}
Release:        1%{?dist}
Summary:        Deterministic replay of distributed system incidents
License:        Apache-2.0
URL:            https://github.com/anduaura/rewind
Source0:        rewind-%{version}-linux-%{arch}

BuildArch:      %{arch}

%description
rewind attaches an eBPF agent to running containers and captures all
inter-service HTTP/gRPC traffic, outbound DB calls, and non-deterministic
syscalls. A triggered flush produces a .rwd snapshot that can be replayed
locally to reproduce any production incident exactly.

%install
install -D -m 0755 %{SOURCE0} %{buildroot}%{_bindir}/rewind

%files
%{_bindir}/rewind

%changelog
* Sun Apr 19 2026 andu <andu.ucsd@gmail.com> - %{version}-1
- Initial package release
