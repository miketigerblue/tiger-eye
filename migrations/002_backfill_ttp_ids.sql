-- tiger-eye migration 002: backfill missing ATT&CK IDs in analysis.ttps
--
-- Applies the same _TTP_NAME_TO_ID lookup table used in the Python normaliser
-- to all existing analysis rows where TTP entries have an empty "id" field.

UPDATE analysis
SET ttps = new_ttps.val::json
FROM (
    SELECT
        a.id AS analysis_id,
        jsonb_agg(
            CASE
                WHEN t->>'id' = '' AND lk.ttp_id IS NOT NULL
                THEN jsonb_build_object('id', lk.ttp_id, 'name', t->>'name')
                ELSE t
            END
            ORDER BY elem_idx
        ) AS val
    FROM analysis a,
         jsonb_array_elements(a.ttps::jsonb) WITH ORDINALITY AS elems(t, elem_idx)
    LEFT JOIN (
        VALUES
            -- Core ATT&CK techniques
            ('exploit public-facing application',        'T1190'),
            ('drive-by compromise',                      'T1189'),
            ('supply chain compromise',                  'T1195'),
            ('phishing',                                 'T1566'),
            ('spearphishing',                            'T1566'),
            ('spearphishing attachment',                 'T1566.001'),
            ('spearphishing link',                       'T1566.002'),
            ('spearphishing via service',                'T1566.003'),
            ('command and scripting interpreter',        'T1059'),
            ('powershell',                               'T1059.001'),
            ('windows command shell',                    'T1059.003'),
            ('python',                                   'T1059.006'),
            ('javascript',                               'T1059.007'),
            ('valid accounts',                           'T1078'),
            ('scheduled task/job',                       'T1053'),
            ('boot or logon autostart execution',        'T1547'),
            ('os credential dumping',                    'T1003'),
            ('credential dumping',                       'T1003'),
            ('credential theft',                         'T1003'),
            ('credential harvesting',                    'T1003'),
            ('credential access',                        'T1003'),
            ('application layer protocol',               'T1071'),
            ('remote services',                          'T1021'),
            ('rdp',                                      'T1021.001'),
            ('smb/windows admin shares',                 'T1021.002'),
            ('vnc',                                      'T1021.005'),
            ('data encrypted for impact',                'T1486'),
            ('endpoint denial of service',               'T1499'),
            ('denial of service',                        'T1499'),
            ('network denial of service',                'T1498'),
            ('network dos',                              'T1498'),
            ('distributed denial of service (ddos) attack', 'T1498'),
            ('ddos',                                     'T1498'),
            ('adversary-in-the-middle',                  'T1557'),
            ('obfuscated files or information',          'T1027'),
            ('masquerading',                             'T1036'),
            ('user execution',                           'T1204'),
            ('user execution: malicious link',           'T1204.001'),
            ('user execution: malicious file',           'T1204.002'),
            ('process injection',                        'T1055'),
            ('code injection',                           'T1055'),
            ('exploitation for privilege escalation',    'T1068'),
            ('privilege escalation',                     'T1068'),
            ('local privilege escalation',               'T1068'),
            ('exploitation for client execution',        'T1203'),
            ('exploitation of remote services',          'T1210'),
            ('external remote services',                 'T1133'),
            ('exfiltration over alternative protocol',   'T1048'),
            ('exfiltration over web service',            'T1567'),
            ('data exfiltration',                        'T1048'),
            ('dynamic resolution',                       'T1568'),
            ('fast flux dns',                            'T1568.001'),
            ('ingress tool transfer',                    'T1105'),
            ('non-standard port',                        'T1571'),
            ('remote access software',                   'T1219'),
            ('lateral movement',                         'T1021'),
            ('persistence',                              'T1547'),
            ('social engineering',                       'T1566'),
            ('extortion',                                'T1486'),
            -- CWE-style / freeform names
            ('sql injection',                            'T1190'),
            ('remote code execution',                    'T1210'),
            ('arbitrary code execution',                 'T1203'),
            ('execution of arbitrary code',              'T1203'),
            ('cross-site scripting',                     'T1059.007'),
            ('cross-site scripting (xss)',               'T1059.007'),
            ('authentication bypass',                    'T1078'),
            ('information disclosure',                   'T1005'),
            ('deserialization of untrusted data',        'T1190'),
            ('container escape',                         'T1611'),
            ('prompt injection',                         'T1059'),
            ('brute force',                              'T1110'),
            ('password spraying',                        'T1110.003'),
            ('exploitation for credential access',       'T1212'),
            ('exploitation for defense evasion',         'T1211'),
            ('dll side-loading',                         'T1574.002'),
            ('dll hijacking',                            'T1574.001'),
            ('component object model (com) hijacking',   'T1546.015'),
            ('com hijacking',                            'T1546.015'),
            ('steganography',                            'T1027.003'),
            ('file and directory discovery',              'T1083'),
            ('system/service discovery',                 'T1046'),
            ('network service discovery',                'T1046'),
            ('indicator removal on host',                'T1070'),
            ('account takeover',                         'T1078'),
            ('business email compromise',                'T1566.002'),
            ('dns tunneling',                            'T1071.004'),
            ('directory traversal',                      'T1190'),
            ('path traversal',                           'T1190'),
            ('file upload',                              'T1190'),
            ('heap-based buffer overflow',               'T1203'),
            ('buffer overflow',                          'T1203'),
            ('exploitation for denial of service',       'T1499'),
            ('data breach',                              'T1530'),
            ('web skimming',                             'T1185'),
            ('browser session hijacking',                'T1185'),
            ('evasion',                                  'T1027'),
            ('defense evasion',                          'T1027'),
            ('staged payload execution',                 'T1059')
    ) AS lk(ttp_name, ttp_id)
        ON lower(t->>'name') = lk.ttp_name
    WHERE a.ttps IS NOT NULL
      AND a.ttps::text != '[]'
    GROUP BY a.id
) AS new_ttps
WHERE analysis.id = new_ttps.analysis_id;
