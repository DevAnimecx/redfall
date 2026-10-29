'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

const NAV = [
  { href: '/', label: 'Overview' },
  { href: '/live', label: 'Live' },
  { href: '/findings', label: 'Findings' },
  { href: '/agents', label: 'Agents' },
  { href: '/results', label: 'Results' },
];

export default function SiteHeader() {
  const pathname = usePathname();
  return (
    <div className="header">
      <Link href="/" className="header-brand">
        <span className="header-mark">RedFall</span>
        <span className="header-tag">execution-verified security</span>
      </Link>
      <nav className="header-nav">
        {NAV.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            className={`header-link${pathname === item.href ? ' is-active' : ''}`}
          >
            {item.label}
          </Link>
        ))}
      </nav>
      <div className="header-right">
        <span className="header-version">v0.3.0</span>
      </div>
    </div>
  );
}
