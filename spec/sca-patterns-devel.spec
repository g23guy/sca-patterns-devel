# spec file for package sca-patterns-devel
#
# Copyright (c) 2020-2023 SUSE LINUX GmbH, Nuernberg, Germany.
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
%define patdocs %{_docdir}/%{name}
%define pythondir %{_libexecdir}/python3.6/site-packages

Name:         sca-patterns-devel
Version:      2.0.1
Release:      0
Summary:      Supportconf Analysis Pattern Development Tools
License:      GPL-2.0-only
URL:          https://github.com/g23guy/sca-patterns-devel
Group:        System/Monitoring
Source:       %{name}-%{version}.tar.gz
Requires:     %{_bindir}/git
Requires:     %{_bindir}/python3
Requires:     %{_bindir}/w3m
Requires:     python3 == 3.6
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
mkdir -p %{buildroot}%{pythondir}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_sbindir}
mkdir -p %{buildroot}%{patdevbasedir}
mkdir -p %{buildroot}%{patdevbasedir}/repos
mkdir -p %{buildroot}%{patdevbasedir}/patterns
mkdir -p %{buildroot}%{patdevbasedir}/forks
mkdir -p %{buildroot}%{patdevbasedir}/archives
mkdir -p %{buildroot}%{patdevbasedir}/duplicates
mkdir -p %{buildroot}%{patdevbasedir}/errors
mkdir -p %{buildroot}%{patdevbasedir}/logs
mkdir -p %{buildroot}%{patdevconfdir}
mkdir -p %{buildroot}%{patdocs}
mkdir -p %{buildroot}%{patdocs}/python
mkdir -p %{buildroot}%{patdocs}/perl
install -m 755 bin/* %{buildroot}%{_bindir}
install -m 755 sbin/* %{buildroot}%{_sbindir}
install -m 664 conf/* %{buildroot}%{patdevconfdir}
install -m 644 lib/* %{buildroot}%{pythondir}
install -m 644 docs/python/* %{buildroot}%{patdocs}/python
install -m 644 docs/perl/* %{buildroot}%{patdocs}/perl
install -m 644 docs/alias %{buildroot}%{patdocs}
install -m 644 docs/index.html %{buildroot}%{patdocs}

%files
%defattr(-,root,root,-)
%dir %{patdevbasedir}
%dir %{patdevconfdir}
%dir %{patdocs}
%dir %{_bindir}
%dir %{_sbindir}
%dir %{_libexecdir}
%{_bindir}/*
%{_sbindir}/*
%{_libexecdir}/*
%{patdocs}/*
%attr(775,root,users) %{patdevbasedir}/repos
%attr(775,root,users) %{patdevbasedir}/forks
%attr(775,root,users) %{patdevbasedir}/patterns
%attr(775,root,users) %{patdevbasedir}/archives
%attr(775,root,users) %{patdevbasedir}/duplicates
%attr(775,root,users) %{patdevbasedir}/errors
%attr(775,root,users) %{patdevbasedir}/logs
%config %attr(664,root,users) %{patdevconfdir}/*

%post

%postun

%changelog

