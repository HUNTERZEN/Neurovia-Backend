/**
 * Authoritative Server-Side Service Catalog (INR).
 * Amounts are strictly controlled on the server to prevent client-side price tampering.
 */
const SERVICE_CATALOG = [
  // 01 — Remote Support
  {
    id: 'remote-quick-fix',
    category: 'Remote Support',
    code: '01',
    title: 'Quick Remote Diagnostics & Fix',
    subtitle: 'OS troubleshooting, driver updates, email or printer setup',
    amountInr: 499,
    duration: '30–45 mins',
    features: [
      'Encrypted live screen session',
      'Windows, macOS & Linux support',
      'No fix, no fee guarantee',
    ],
  },
  {
    id: 'remote-virus-opt',
    category: 'Remote Support',
    code: '01',
    title: 'Virus Removal & Full PC Optimization',
    subtitle: 'Deep malware cleanup, startup tune-up & security hardening',
    amountInr: 799,
    duration: '45–60 mins',
    popular: true,
    features: [
      'Complete malware & spyware removal',
      'Thermal & startup speed optimization',
      'Browser & firewall protection check',
    ],
  },
  {
    id: 'remote-video-session',
    category: 'Remote Support',
    code: '01',
    title: 'Live Video Call Support',
    subtitle: 'Face-to-face expert diagnostics with live screen sharing',
    amountInr: 699,
    duration: '30 mins',
    features: [
      'HD video + screen sharing',
      'Step-by-step live explanation',
      'Post-session summary notes',
    ],
  },
  {
    id: 'remote-voice-session',
    category: 'Remote Support',
    code: '01',
    title: 'Voice Call + Remote Control',
    subtitle: 'Direct audio call with guided remote troubleshooting',
    amountInr: 499,
    duration: '30 mins',
    features: [
      'Instant audio connection',
      'Permission-based screen control',
      'Fast issue resolution',
    ],
  },
  {
    id: 'remote-chat-session',
    category: 'Remote Support',
    code: '01',
    title: 'Guided Expert Chat Session',
    subtitle: 'Real-time text support with log & screenshot sharing',
    amountInr: 349,
    duration: '30 mins',
    features: [
      '1-on-1 certified technician chat',
      'Screenshot & diagnostic log review',
      'Written fix checklist',
    ],
  },

  // 02 — Onsite Repair
  {
    id: 'onsite-visit-diag',
    category: 'Onsite Repair',
    code: '02',
    title: 'Doorstep Laptop / Desktop Repair Visit',
    subtitle: 'Certified technician visit + full hardware & OS diagnostics',
    amountInr: 599,
    duration: 'Same-day visit',
    popular: true,
    features: [
      'Certified doorstep technician',
      'Complete hardware health check',
      'Transparent spare-part quote if needed',
    ],
  },
  {
    id: 'onsite-network-wifi',
    category: 'Onsite Repair',
    code: '02',
    title: 'Home & Office WiFi / Network Setup',
    subtitle: 'Router configuration, mesh WiFi, LAN cabling & dead-zone fix',
    amountInr: 1499,
    duration: '1–2 hours',
    features: [
      'Router, mesh & access point setup',
      'WPA3 security & guest network config',
      'Full coverage speed testing',
    ],
  },
  {
    id: 'onsite-data-recovery',
    category: 'Onsite Repair',
    code: '02',
    title: 'Data Recovery & Backup Service',
    subtitle: 'Recover files from corrupted drives, SSDs, or unbootable PCs',
    amountInr: 1999,
    duration: 'Assessment + recovery',
    features: [
      'Safe non-destructive sector read',
      'OS crash & accidental deletion recovery',
      'Cloud / external drive backup setup',
    ],
  },
  {
    id: 'onsite-cctv-setup',
    category: 'Onsite Repair',
    code: '02',
    title: 'CCTV & Smart Security Installation',
    subtitle: 'IP/HD camera setup, NVR/DVR config & mobile live-view app',
    amountInr: 2499,
    duration: 'Half-day setup',
    features: [
      'Up to 4 cameras configuration',
      'Phone remote viewing setup',
      'Motion alerts & storage tuning',
    ],
  },

  // 03 — Business IT
  {
    id: 'biz-cyber-audit',
    category: 'Business IT',
    code: '03',
    title: 'Cybersecurity & Endpoint Audit',
    subtitle: 'Vulnerability scan, ransomware readiness & access hardening',
    amountInr: 4999,
    duration: 'Comprehensive audit',
    features: [
      'Network & endpoint vulnerability report',
      'Email security (SPF/DKIM/DMARC) check',
      'Executive remediation roadmap',
    ],
  },
  {
    id: 'biz-amc-starter',
    category: 'Business IT',
    code: '03',
    title: 'Business IT AMC (Starter — Up to 10 Devices)',
    subtitle: 'Monthly managed IT support, priority SLA & preventive maintenance',
    amountInr: 7999,
    duration: 'Monthly plan',
    popular: true,
    features: [
      'Unlimited remote support tickets',
      'Scheduled onsite health visits',
      'Server, backup & employee helpdesk',
    ],
  },
  {
    id: 'biz-server-setup',
    category: 'Business IT',
    code: '03',
    title: 'Office IT & Server Infrastructure Setup',
    subtitle: 'Workstations, NAS/server admin, VPN & automated disaster backup',
    amountInr: 9999,
    duration: 'Project deployment',
    features: [
      'Complete office network & server setup',
      'Automated 3-2-1 backup architecture',
      'Role-based employee access control',
    ],
  },

  // 04 — Software & Cloud
  {
    id: 'dev-cloud-migration',
    category: 'Software & Cloud',
    code: '04',
    title: 'Cloud Architecture & Migration Kickoff',
    subtitle: 'AWS / Azure / GCP architecture blueprint, cost optimization & setup',
    amountInr: 3999,
    duration: 'Architecture + setup',
    features: [
      'Cloud readiness & cost audit',
      'CI/CD & SSL domain deployment',
      'Zero-downtime migration plan',
    ],
  },
  {
    id: 'dev-website-starter',
    category: 'Software & Cloud',
    code: '04',
    title: 'Business Website / Web App Kickoff',
    subtitle: 'Modern responsive web build — discovery, UI prototype & milestone 1',
    amountInr: 4999,
    duration: 'Project kickoff deposit',
    popular: true,
    features: [
      'Custom responsive UI/UX design',
      'SEO, speed & mobile optimization',
      'Dedicated Neurovia engineering lead',
    ],
  },
  {
    id: 'dev-ai-automation',
    category: 'Software & Cloud',
    code: '04',
    title: 'AI Chatbot & Workflow Automation',
    subtitle: 'Custom AI support bot + WhatsApp/CRM workflow integration kickoff',
    amountInr: 5999,
    duration: 'Project kickoff deposit',
    features: [
      'Trained on your business knowledge base',
      'Website / WhatsApp / lead capture sync',
      'Analytics & human-handoff support',
    ],
  },
];

function getServiceById(serviceId) {
  if (typeof serviceId !== 'string') return null;
  return SERVICE_CATALOG.find((s) => s.id === serviceId.trim()) || null;
}

module.exports = {
  SERVICE_CATALOG,
  getServiceById,
};

