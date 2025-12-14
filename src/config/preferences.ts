export const LANGUAGES = [
  { code: 'en', label: 'English' },
  { code: 'es', label: 'Spanish' },
  { code: 'fr', label: 'French' },
  { code: 'de', label: 'German' },
  { code: 'zh', label: 'Chinese (Simplified)' },
  { code: 'zh-Hant', label: 'Chinese (Traditional)' },
  { code: 'ja', label: 'Japanese' },
  { code: 'ko', label: 'Korean' },
  { code: 'pt', label: 'Portuguese' },
  { code: 'ru', label: 'Russian' },
  { code: 'ar', label: 'Arabic' },
  { code: 'hi', label: 'Hindi' },
  { code: 'it', label: 'Italian' },
  { code: 'nl', label: 'Dutch' },
  { code: 'sv', label: 'Swedish' }
];

const TIMEZONE_IDS = [
  'UTC',
  'Etc/GMT+12',
  'Etc/GMT+11',
  'Pacific/Honolulu',
  'America/Anchorage',
  'America/Los_Angeles',
  'America/Denver',
  'America/Chicago',
  'America/New_York',
  'America/Sao_Paulo',
  'Europe/London',
  'Europe/Paris',
  'Europe/Berlin',
  'Europe/Madrid',
  'Europe/Rome',
  'Europe/Amsterdam',
  'Europe/Stockholm',
  'Europe/Istanbul',
  'Africa/Cairo',
  'Africa/Johannesburg',
  'Asia/Jerusalem',
  'Asia/Dubai',
  'Asia/Kolkata',
  'Asia/Bangkok',
  'Asia/Singapore',
  'Asia/Shanghai',
  'Asia/Tokyo',
  'Asia/Seoul',
  'Australia/Sydney',
  'Pacific/Auckland'
];

function getOffsetMinutes(timeZone: string) {
  try {
    const now = new Date();
    const dtf = new Intl.DateTimeFormat('en-US', {
      timeZone,
      hour12: false,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
    const parts = dtf.formatToParts(now);
    const filled: Record<string, string> = {};
    for (const part of parts) {
      if (part.type !== 'literal') filled[part.type] = part.value;
    }
    const asUTC = Date.UTC(
      Number(filled.year),
      Number(filled.month) - 1,
      Number(filled.day),
      Number(filled.hour),
      Number(filled.minute),
      Number(filled.second)
    );
    const diff = asUTC - now.getTime(); // positive = tz ahead of UTC
    return Math.round(diff / 60000);
  } catch {
    return 0;
  }
}

function formatOffset(minutes: number) {
  const sign = minutes >= 0 ? '+' : '-';
  const abs = Math.abs(minutes);
  const hrs = String(Math.floor(abs / 60)).padStart(2, '0');
  const mins = String(abs % 60).padStart(2, '0');
  return `${sign}${hrs}:${mins}`;
}

export const TIMEZONES = TIMEZONE_IDS.map((tz) => {
  const offset = getOffsetMinutes(tz);
  const offsetLabel = formatOffset(offset);
  return {
    id: tz,
    label: `${tz} (UTC${offsetLabel})`,
    offsetMinutes: offset
  };
});

export const COUNTRY_CODES = [
  { code: '+1', label: 'United States / Canada (+1)' },
  { code: '+44', label: 'United Kingdom (+44)' },
  { code: '+61', label: 'Australia (+61)' },
  { code: '+64', label: 'New Zealand (+64)' },
  { code: '+81', label: 'Japan (+81)' },
  { code: '+82', label: 'South Korea (+82)' },
  { code: '+86', label: 'China (+86)' },
  { code: '+852', label: 'Hong Kong (+852)' },
  { code: '+853', label: 'Macau (+853)' },
  { code: '+886', label: 'Taiwan (+886)' },
  { code: '+91', label: 'India (+91)' },
  { code: '+92', label: 'Pakistan (+92)' },
  { code: '+94', label: 'Sri Lanka (+94)' },
  { code: '+65', label: 'Singapore (+65)' },
  { code: '+60', label: 'Malaysia (+60)' },
  { code: '+62', label: 'Indonesia (+62)' },
  { code: '+63', label: 'Philippines (+63)' },
  { code: '+66', label: 'Thailand (+66)' },
  { code: '+971', label: 'UAE (+971)' },
  { code: '+972', label: 'Israel (+972)' },
  { code: '+90', label: 'Turkey (+90)' },
  { code: '+27', label: 'South Africa (+27)' },
  { code: '+234', label: 'Nigeria (+234)' },
  { code: '+55', label: 'Brazil (+55)' },
  { code: '+52', label: 'Mexico (+52)' },
  { code: '+34', label: 'Spain (+34)' },
  { code: '+33', label: 'France (+33)' },
  { code: '+49', label: 'Germany (+49)' },
  { code: '+39', label: 'Italy (+39)' },
  { code: '+31', label: 'Netherlands (+31)' },
  { code: '+46', label: 'Sweden (+46)' },
  { code: '+47', label: 'Norway (+47)' },
  { code: '+45', label: 'Denmark (+45)' },
  { code: '+48', label: 'Poland (+48)' },
  { code: '+7', label: 'Russia (+7)' },
  { code: '+420', label: 'Czech Republic (+420)' },
  { code: '+41', label: 'Switzerland (+41)' },
  { code: '+353', label: 'Ireland (+353)' },
  { code: '+351', label: 'Portugal (+351)' },
  { code: '+966', label: 'Saudi Arabia (+966)' },
  { code: '+20', label: 'Egypt (+20)' }
];
