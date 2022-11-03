# spec file for package sca-patterns-devel
#
# Copyright (c) 2020-2022 SUSE LINUX GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

%define patdevbase patdevel
%define patdevbasedir %{_localstatedir}/opt/%{patdevbase}
%define patdevconfdir %{_sysconfdir}/opt/%{patdevbase}

Name:         sca-patterns-devel
Version:      1.2.8
Release:      0
Summary:      Supportconf Analysis Pattern Development Tools
License:      GPL-2.0-only
URL:          https://github.com/g23guy/sca-patterns-devel
Group:        System/Monitoring
Source:       %{name}-%{version}.tar.gz
Requires:     /usr/bin/git
Requires:     /usr/bin/python3
Requires:     /usr/bin/w3m
BuildArch:    noarch

%description
Tools used in the creation and testing of supportconfig analysis patterns for the SCA Tool.

%prep
%setup -q

%build

%install
pwd;ls -la
#install -d %{buildroot}%{_mandir}/man5
#install -d %{buildroot}%{_mandir}/man8
mkdir -p %{buildroot}/usr/local/bin
mkdir -p %{buildroot}%{patdevbasedir}
mkdir -p %{buildroot}%{patdevbasedir}/repos
mkdir -p %{buildroot}%{patdevbasedir}/patterns
mkdir -p %{buildroot}%{patdevbasedir}/forks
mkdir -p %{buildroot}%{patdevbasedir}/archives
mkdir -p %{buildroot}%{patdevconfdir}
install -m 755 bin/* %{buildroot}/usr/local/bin
install -m 664 conf/* %{buildroot}%{patdevconfdir}

%files
%defattr(-,root,root,-)
%dir %{patdevbasedir}
%dir %{patdevconfdir}
%{patdevbasedir}/*
/usr/local/bin/*
%attr(775,root,users) %{patdevbasedir}/repos
%attr(775,root,users) %{patdevbasedir}/forks
%attr(775,root,users) %{patdevbasedir}/patterns
%attr(775,root,users) %{patdevbasedir}/archives
%config %attr(664,root,users) %{patdevconfdir}/*

%post

%postun

%changelog

