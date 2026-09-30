/**
 * First word of the Unicode character name for every alphabetic code point,
 * i.e. what Python's `unicodedata.name(ch).split(" ")[0]` returns for chars
 * where `ch.isalpha()` ("LATIN", "CYRILLIC", "GREEK", "CJK", "MODIFIER", ...).
 *
 * GENERATED from Python 3.12.11 unicodedata (Unicode 15.0.0) so
 * `mixedScripts` reproduces the Python engine exactly; do not edit by hand.
 * Encoding: comma-separated runs `<hex delta from previous run start>[:<hex word index>]`;
 * a run without a word index is non-alphabetic (skipped).
 */

export const NAME_WORDS: readonly string[] = [
  "ADLAM", "AHOM", "ALEF", "ANATOLIAN", "ANGSTROM", "ARABIC", "ARMENIAN", "AVESTAN", "BALINESE",
  "BAMUM", "BASSA", "BATAK", "BENGALI", "BET", "BHAIKSUKI", "BLACK-LETTER", "BOPOMOFO", "BRAHMI",
  "BUGINESE", "BUHID", "CANADIAN", "CARIAN", "CARON", "CAUCASIAN", "CHAKMA", "CHAM", "CHEROKEE",
  "CHORASMIAN", "CJK", "COPTIC", "CUNEIFORM", "CYPRIOT", "CYPRO-MINOAN", "CYRILLIC", "DALET",
  "DESERET", "DEVANAGARI", "DIVES", "DOGRA", "DOUBLE-STRUCK", "DUPLOYAN", "EGYPTIAN", "ELBASAN",
  "ELYMAIC", "ETHIOPIC", "EULER", "FEMININE", "FULLWIDTH", "GEORGIAN", "GIMEL", "GLAGOLITIC",
  "GOTHIC", "GRANTHA", "GREEK", "GUJARATI", "GUNJALA", "GURMUKHI", "HALFWIDTH", "HANGUL", "HANIFI",
  "HANUNOO", "HATRAN", "HEBREW", "HENTAIGANA", "HIRAGANA", "IDEOGRAPHIC", "IMPERIAL",
  "INFORMATION", "INSCRIPTIONAL", "JAVANESE", "KAITHI", "KANNADA", "KATAKANA", "KATAKANA-HIRAGANA",
  "KAWI", "KAYAH", "KELVIN", "KHAROSHTHI", "KHITAN", "KHMER", "KHOJKI", "KHUDAWADI", "LAO",
  "LATIN", "LEPCHA", "LIMBU", "LINEAR", "LISU", "LYCIAN", "LYDIAN", "MAHAJANI", "MAKASAR",
  "MALAYALAM", "MANDAIC", "MANICHAEAN", "MARCHEN", "MASARAM", "MASCULINE", "MASU", "MATHEMATICAL",
  "MEDEFAIDRIN", "MEETEI", "MENDE", "MEROITIC", "MIAO", "MICRO", "MODI", "MODIFIER", "MONGOLIAN",
  "MRO", "MULTANI", "MYANMAR", "NABATAEAN", "NAG", "NANDINAGARI", "NEW", "NEWA", "NKO", "NUSHU",
  "NYIAKENG", "OGHAM", "OHM", "OL", "OLD", "ORIYA", "OSAGE", "OSMANYA", "PAHAWH", "PALMYRENE",
  "PAU", "PHAGS-PA", "PHOENICIAN", "PLANCK", "PSALTER", "REJANG", "ROMAN", "RUNIC", "SAMARITAN",
  "SAURASHTRA", "SCRIPT", "SHARADA", "SHAVIAN", "SIDDHAM", "SINHALA", "SOGDIAN", "SORA", "SOYOMBO",
  "SUNDANESE", "SUPERSCRIPT", "SYLOTI", "SYRIAC", "TAGALOG", "TAGBANWA", "TAI", "TAKRI", "TAMIL",
  "TANGSA", "TANGUT", "TELUGU", "THAANA", "THAI", "TIBETAN", "TIFINAGH", "TIRHUTA", "TOTO",
  "TURNED", "UGARITIC", "UNKNOWN", "VAI", "VEDIC", "VERTICAL", "VITHKUQI", "WANCHO", "WARANG",
  "YEZIDI", "YI", "ZANABAZAR",
];

const RUNS =
  "0,41:53,1a,6:53,1a,2f:2e,1,a:69,1,4:61,1,5:53,17,1:53,1f,1:53,1b8:6b,12,4:6b,1:16,1:6b,a,e:6b,5," +
  "7:6b,1,1:6b,1,81:35,5,1:35,2,2:35,4,1:35,1,6:35,1,1:35,3,1:35,1,1:35,14,1:35,3f:1d,e:35,6,1:35,9" +
  ":21,82,8:21,a6,1:6,26,2:6,1,6:6,29,47:3e,1b,4:3e,4,2d:5,2b,23:5,2,1:5,63,1:5,1,f:5,2,7:5,2,a:5,3" +
  ",2:5,1,10:96,1,1:96,1e,1d:96,3:5,30:9f,26,b:9f,1,18:75,21,9:75,2,4:75,1,5:89,16,4:89,1,9:89,1,3:" +
  "89,1,17:5d,19,7:96,b,5:5,18,1:5,6,11:5,2a,3a:24,36,3:24,1,12:24,1,7:24,a,f:24,f:c,1,4:c,8,2:c,2," +
  "2:c,16,1:c,7,1:c,1,3:c,4,3:c,1,10:c,1,d:c,2,1:c,3,e:c,2,a:c,1,8:38,6,4:38,2,2:38,16,1:38,7,1:38," +
  "2,1:38,2,1:38,2,1f:38,4,1:38,1,13:38,3,10:36,9,1:36,3,1:36,16,1:36,7,1:36,2,1:36,5,3:36,1,12:36," +
  "1,f:36,2,17:36,1,b:7c,8,2:7c,2,2:7c,16,1:7c,7,1:7c,2,1:7c,5,3:7c,1,1e:7c,2,1:7c,3,f:7c,1,11:9b,1" +
  ",1:9b,6,3:9b,3,1:9b,4,3:9b,2,1:9b,1,1:9b,2,3:9b,2,3:9b,3,3:9b,c,16:9b,1,34:9e,8,1:9e,3,1:9e,17,1" +
  ":9e,10,3:9e,1,1a:9e,3,2:9e,1,2:9e,2,1e:47,1,4:47,8,1:47,3,1:47,17,1:47,a,1:47,5,3:47,1,1f:47,2,1" +
  ":47,2,f:47,2,11:5c,9,1:5c,3,1:5c,29,2:5c,1,10:5c,1,5:5c,3,8:5c,3,18:5c,6,5:8f,12,3:8f,18,1:8f,9," +
  "1:8f,1,2:8f,7,3a:a0,30,1:a0,2,c:a0,7,3a:52,2,1:52,1,1:52,5,1:52,18,1:52,1,1:52,a,1:52,2,9:52,1,2" +
  ":52,5,1:52,1,15:52,4,20:a1,1,3f:a1,8,1:a1,24,1b:a1,5,73:6f,2b,14:6f,1,10:6f,6,4:6f,4,3:6f,1,3:6f" +
  ",2,7:6f,3,4:6f,d,c:6f,1,11:30,26,1:30,1,5:30,1,2:30,2b,1:6b,1:30,3:3a,100:2c,49,1:2c,4,2:2c,7,1:" +
  "2c,1,1:2c,4,2:2c,29,1:2c,4,2:2c,21,1:2c,4,2:2c,7,1:2c,1,1:2c,4,2:2c,f,1:2c,39,1:2c,4,2:2c,43,25:" +
  "2c,10,10:1a,56,2:1a,6,3:14,26c,2:14,11,1:78,1a,5:88,4b,6:88,8,7:97,12,d:97,1:3c,12,e:13,12,e:98," +
  "d,1:98,3,f:4f,34,23:4f,1,4:4f,1,43:6c,59,7:6c,5,2:6c,22,1:6c,1,5:14,46,a:55,1f,31:99,1e,2:99,5,b" +
  ":73,2c,4:73,1a,36:12,17,9:99,35,52:99,1,5d:8,2f,11:8,8,36:93,1e,d:93,2,a:93,6:b,26,1a:54,24,29:5" +
  "4,3,a:7a,24,2:21,9,7:30,2b,2:30,3,29:a9,4,1:a9,6,1:a9,2,3:a9,1,5:53,26:35,5:21,1:6b,36:53,4:35,5" +
  ":53,d:6b,1:53,22:6b,25,40:53,100:35,16,2:35,6,2:35,26,2:35,6,2:35,8,1:35,1,1:35,1,1:35,1,1:35,1f" +
  ",2:35,35,1:35,7,1:35,1,3:35,3,1:35,7,3:35,4,2:35,6,4:35,d,5:35,3,1:35,7,74:94,1,d:94,1,10:53,d,6" +
  "5:27,1,4:2d,1,2:8b,2:f,1:27,1:84,2:8b,1:f,1:8b,2,1:27,1,3:27,2:8b,1:f,1:27,1,6:27,1,1:79,1,1:f,1" +
  ",1:4c,1:4,1:8b,1:f,1,1:8b,3:a5,1:8b,2:2,1:d,1:31,1:22,1:43,1,2:27,4,5:27,5,4:a5,1,34:87,1:53,1,a" +
  "7b:32,60:53,1d:6b,1:53,2:1d,65,6:1d,4,3:1d,2,c:30,26,1:30,1,5:30,1,2:a2,38,7:a2,1,10:2c,17,9:2c," +
  "7,1:2c,7,1:2c,7,1:2c,7,1:2c,7,1:2c,7,1:2c,7,1:2c,7,50:aa,1,1d5:41,2,2a:aa,5,5:aa,1:62,1,4:40,56," +
  "6:40,3,1:48,5a,1:49,1:48,3,5:10,2b,1:3a,5e,11:10,20,30:48,10,200:1c,19c0,40:1c,5200:af,48d,43:57" +
  ",2e,2:a8,10d,3:a8,10,a:a8,2,14:21,2f,10:21,1d:6b,2,2:9,46,31:6b,9,2:53,4e:6b,1:53,17:6b,1,2:53,4" +
  "0,5:53,2,1:53,1,1:53,5,18:6b,3:53,3:6b,2:53,6:95,2,1:95,3,1:95,4,1:95,17,1d:82,34,e:8a,32,3e:24," +
  "6,3:24,1,1:24,2,b:4b,1c,a:86,17,19:3a,1d,7:45,2f,1c:45,1,10:6f,5,1:6f,a,a:6f,5,1:19,29,17:19,3,1" +
  ":19,8,14:6f,17,3:6f,1,3:6f,2:99,30,1:99,1,3:99,2,2:99,5,2:99,1,1:99,1,18:99,3,2:65,b,7:65,3,c:2c" +
  ",6,2:2c,6,2:2c,6,9:2c,7,1:2c,7,1:53,2b,1:6b,4:53,5:35,1:53,3:6b,1,6:1a,50:65,23,1d:3a,2ba4,c:3a," +
  "17,4:3a,31,2104:1c,16e,2:1c,6a,26:53,7,c:6,5,5:3e,1,1:3e,a,1:3e,d,1:3e,5,1:3e,1,1:3e,2,1:3e,2,1:" +
  "3e,a:5,62,21:5,16b,12:5,40,2:5,36,28:5,c,74:5,5,1:5,87,24:2f,1a,6:2f,1a,b:39,59,3:39,6,2:39,6,2:" +
  "39,6,2:39,3,23:56,c,1:56,1a,1:56,13,1:56,2,1:56,f,2:56,e,22:56,7b,185:58,1d,3:15,31,2f:7b,20,d:7" +
  "b,3:33,11,1:33,8,6:7b,26,a:a6,1e,2:7b,24,4:7b,8,30:23,50:8d,30:7e,1e,12:7d,24,4:7d,24,4:2a,28,8:" +
  "17,34,c:ab,b,1:ab,f,1:ab,7,1:ab,2,1:ab,b,1:ab,f,1:ab,7,1:ab,2,43:56,137,9:56,16,a:56,8,18:6b,6,1" +
  ":6b,2a,1:6b,9,45:1f,6,2:1f,1,1:1f,2c,1:1f,2,3:1f,1,2:1f,1:42,16,a:80,17,9:70,1f,41:3d,13,1:3d,2," +
  "a:83,16,a:59,1a,46:67,38,6:67,2,40:4d,1,f:4d,4,1:4d,3,1:4d,1d,2a:7b,1d,3:7b,1d,23:5e,8,1:5e,1c,1" +
  "b:7,36,a:44,16,a:44,13,d:85,12,6e:7b,49,37:7b,33,d:7b,33,d:3b,24,15c:ae,2a,6:ae,2,4e:7b,1d,a:7b," +
  "1,8:90,16,2a:7b,12,2e:1b,15,1b:2b,17,c:11,35,39:11,2,2:11,1,d:46,2d,20:91,19,1a:18,24,1d:18,1,2:" +
  "18,1,8:5a,23,3:5a,1,c:8c,30,e:8c,4,15:8c,1,1:8c,1,23:50,12,1:50,19,13:50,2,3f:6e,7,1:6e,1,1:6e,4" +
  ",1:6e,f,1:6e,a,7:51,2f,26:34,8,2:34,2,2:34,16,1:34,7,1:34,2,1:34,5,3:34,1,12:34,1,c:34,5,9e:74,3" +
  "5,12:74,4,14:74,3,1e:a3,30,14:a3,2,1:a3,1,b8:8e,2f,29:8e,4,24:6a,30,14:6a,1,3b:9a,2b,d:9a,1,47:1" +
  ",1b,25:1,7,b9:26,2c,74:ad,40,1f:ad,1:25,7,2:25,1,2:25,8,1:25,2,1:25,18,f:25,1,1:25,1,5e:72,8,2:7" +
  "2,27,10:72,1,1:72,1,1c:b0,1,a:b0,28,7:b0,1,15:92,1,b:92,2e,13:92,1,12:14,10:81,39,107:e,9,1:e,25" +
  ",11:e,1,31:5f,1e,70:60,7,1:60,2,1:60,26,15:60,1,19:37,6,1:37,2,1:37,20,e:37,1,147:5b,13,f:4a,1,1" +
  ":4a,d,1:4a,22,7c:57,1,4f:1e,39a,e6:1e,c4,a4c:20,61,f:29,430,11:29,6,fb9:3,247,21b9:9,239,7:6d,1f" +
  ",11:9c,4f,11:a,1e,12:7f,30,10:7f,4,1f:7f,15,5:7f,13,2b0:64,40,80:68,4b,5:68,1,42:68,d,40:9d,1:76" +
  ",1,1:7b,1,1c:a7,17f8,8:9d,300:4e,1d6,2a:a7,9,22e7:48,4,1:48,7,1:48,2,1:48,1:40,1:3f,11d:40,1:48," +
  "3,f:40,1,1d:40,3,2:48,1,e:48,4,8:76,18c,904:28,6b,5:28,d,3:28,9,7:28,a,1766:63,55,1:63,47,1:63,2" +
  ",2:63,1,2:63,2,2:63,4,1:63,c,1:63,1,1:63,7,1:63,41,1:63,4,2:63,8,1:63,7,1:63,1c,1:63,4,1:63,5,1:" +
  "63,1,3:63,7,1:63,154,2:63,19,1:63,19,1:63,1f,1:63,19,1:63,1f,1:63,19,1:63,1f,1:63,19,1:63,1f,1:6" +
  "3,19,1:63,8,734:53,1f,6:53,6,105:6b,21:21,1a:6b,3,92:77,2d,a:77,7,10:77,1,141:a4,1e,12:ac,2c,1e4" +
  ":71,1c,2f4:2c,7,1:2c,4,1:2c,2,1:2c,f,1:66,c5,3b:0,44,7:0,1,4b4:5,4,1:5,1b,1:5,2,1:5,1,2:5,1,1:5," +
  "a,1:5,4,1:5,1,1:5,1,6:5,1,4:5,1,1:5,1,1:5,1,1:5,3,1:5,2,1:5,1,2:5,1,1:5,1,1:5,1,1:5,1,1:5,1,1:5," +
  "2,1:5,1,2:5,4,1:5,7,1:5,4,1:5,4,1:5,1,1:5,a,1:5,11,5:5,3,1:5,5,1:5,11,1144:1c,a6e0,20:1c,103a,6:" +
  "1c,de,2:1c,1682,e:1c,1d31,c1f:1c,21e,5e2:1c,134b,5:1c,1060";

const STARTS: number[] = [];
const WORDS: Array<string | null> = [];
{
  let cp = 0;
  for (const entry of RUNS.split(",")) {
    const [delta, word] = entry.split(":");
    cp += parseInt(delta, 16);
    STARTS.push(cp);
    WORDS.push(word === undefined ? null : NAME_WORDS[parseInt(word, 16)]);
  }
}

/**
 * Python `unicodedata.name(ch).split(" ")[0]` for an alphabetic `ch`, or `null`
 * when `ch.isalpha()` is false (Python's `mixed_scripts` skips those).
 */
export function nameWord(ch: string): string | null {
  const cp = ch.codePointAt(0);
  if (cp === undefined) return null;
  let lo = 0;
  let hi = STARTS.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (STARTS[mid] <= cp) lo = mid;
    else hi = mid - 1;
  }
  return WORDS[lo];
}
