# coding=utf-8
"""
Declares all airfields in Caucasus
"""
from ._univers_radio import Airfield, URCoord, URFrequency

# noinspection SpellCheckingInspection
UG5X = Airfield('UG5X', 'Kobuleti',
                URCoord('41.929501', '41.871101', '59'),
                URFrequency('133.300;A'),
                '07,25')
# noinspection SpellCheckingInspection
UG23 = Airfield('UG23', 'Gudauta',
                URCoord('43.101501', '40.581299', '68'),
                URFrequency('130.300;A'),
                '15,33')
# noinspection SpellCheckingInspection
UG24 = Airfield('UG24', 'Tbilisi - Soganlug',
                URCoord('41.649200', '44.933701', '1472'),
                URFrequency('139.300;A'),
                '13,31')
# noinspection SpellCheckingInspection
UG27 = Airfield('UG27', 'Vaziani',
                URCoord('41.628300', '45.030201', '1492'),
                URFrequency('140.300;A'),
                '13,31')
# noinspection SpellCheckingInspection
UGKO = Airfield('UGKO', 'Kutaisi - Kopitnari',
                URCoord('42.178699', '42.483101', '147'),
                URFrequency('134.300;A'),
                '08,26')
# noinspection SpellCheckingInspection
UGKS = Airfield('UGKS', 'Senaki - Kolkhi',
                URCoord('42.240101', '42.052101', '42'),
                URFrequency('132.300;A'),
                '09,17')
# noinspection SpellCheckingInspection
UGSB = Airfield('UGSB', 'Batumi',
                URCoord('41.610802', '41.598202', '32'),
                URFrequency('131.300;A'),
                '12,30')
# noinspection SpellCheckingInspection
UGSS = Airfield('UGSS', 'Sukhumi - Babushara',
                URCoord('42.867100', '41.120602', '29'),
                URFrequency('129.300;A'),
                '11,29')
# noinspection SpellCheckingInspection
UGTB = Airfield('UGTB', 'Tbilisi - Lochini',
                URCoord('41.673199', '44.953499', '1538'),
                URFrequency('138.300;A'),
                '13R,31L')
# noinspection SpellCheckingInspection
URKA = Airfield('URKA', 'Anapa - Vityazevo',
                URCoord('45.002899', '37.340801', '147'),
                URFrequency('121.300;A'),
                '04,22')
# noinspection SpellCheckingInspection
URKG = Airfield('URKG', 'Geledzhik',
                URCoord('44.592300', '38.023300', '82'),
                URFrequency('126.300;A'),
                '04,22')
# noinspection SpellCheckingInspection
URKH = Airfield('URKH', 'Maykop - Khanskaya',
                URCoord('44.681400', '40.032501', '590'),
                URFrequency('125.300;A'),
                '04,22')
# noinspection SpellCheckingInspection
URKK = Airfield('URKK', 'Krasnodar - Pashkovsky',
                URCoord('45.035999', '39.146702', '111'),
                URFrequency('128.300;A'),
                '04L,22R,04R,22L')
# noinspection SpellCheckingInspection
URKL = Airfield('URKL', 'Krasnodar - Center',
                URCoord('45.080700', '38.961899', '98'),
                URFrequency('122.300;A'),
                '08,26')
# noinspection SpellCheckingInspection
URKN = Airfield('URKN', 'Novorossiysk',
                URCoord('44.678398', '37.782501', '131'),
                URFrequency('123.300;A'),
                '04,22')
# noinspection SpellCheckingInspection
URKW = Airfield('URKW', 'Krymsk',
                URCoord('44.958500', '37.996601', '65'),
                URFrequency('124.300;A'),
                '03,21')
# noinspection SpellCheckingInspection
URMM = Airfield('URMM', 'Mineralnye Vody',
                URCoord('44.219501', '43.085899', '1049'),
                URFrequency('135.300;A'),
                '11,29')
# noinspection SpellCheckingInspection
URMN = Airfield('URMN', 'Nalchik',
                URCoord('43.511200', '43.635201', '1410'),
                URFrequency('136.300;A'),
                '05,23')
# noinspection SpellCheckingInspection
URMO = Airfield('URMO', 'Beslan',
                URCoord('43.203899', '44.608398', '1908'),
                URFrequency('141.300;A'),
                '09,27')
# noinspection SpellCheckingInspection
URSS = Airfield('URSS', 'Sochi - Adler',
                URCoord('43.443501', '39.941502', '98'),
                URFrequency('127.300;A'),
                '02,20,06,24')
# noinspection SpellCheckingInspection
XRMF = Airfield('XRMF', 'Mozdok',
                URCoord('43.786201', '44.607201', '508'),
                URFrequency('137.300;A'),
                '08,26')
# noinspection SpellCheckingInspection
# https://skyvector.com/airport/INS/Creech-AFB-Airport
KINS = Airfield('KINS', 'Creech Air Force Base',
                URCoord('36.586300', '-115.677399', '3132'),
                URFrequency('290.450;A'),
                '08,26,13,31')
# noinspection SpellCheckingInspection
# https://skyvector.com/airport/LAS/Mc-Carran-International-Airport
KLAS = Airfield('KLAS', 'Mac Carran International Airport',
                URCoord('36.080101', '-115.152199', '2181'),
                URFrequency('120.775;A'),
                '01L,01R,07L,07R,19L,19R,25L,25R')
# noinspection SpellCheckingInspection
# https://skyvector.com/airport/LSV/Nellis-AFB-Airport
KLSV = Airfield('KLSV', 'Nellis Air Force Base',
                URCoord('36.236198', '-115.034302', '1869'),
                URFrequency('270.100;A'),
                '03L,03R,21L,21R')
# noinspection SpellCheckingInspection
KXTA = Airfield('KXTA', 'Groom Lake Air Force Base',
                URCoord('37.233299', '-115.799400', '4493'),
                URFrequency('123.500;A'),
                '14L,32R')
# noinspection SpellCheckingInspection
# https://skyvector.com/airport/BTY/Beatty-Airport
KBTY = Airfield('KBTY', 'Beatty Airport',
                URCoord('36.866501', '-116.784698', '3168'),
                URFrequency('290.450;A'),
                '09,34')
# noinspection SpellCheckingInspection
# https://skyvector.com/airport/BVU/Boulder-City-Municipal-Airport
KBVU = Airfield('KBVU', 'Boulder City Municipal Airport',
                URCoord('35.947399', '-114.861397', '2200'),
                URFrequency('120.775;A'),
                '09,27,15,33')
# noinspection SpellCheckingInspection
# https://skyvector.com/airport/0L9/Echo-Bay-Airport
K0L9 = Airfield('K0L9', 'Echo Bay Airport',
                URCoord('36.311100', '-114.463799', '1531'),
                URFrequency('270.100;A'),
                '06,24')
# noinspection SpellCheckingInspection
# https://skyvector.com/airport/HND/Henderson-Executive-Airport
KHND = Airfield('KHND', 'Henderson Executive Airport',
                URCoord('35.972698', '-115.134399', '2492'),
                URFrequency('120.775;A'),
                '17L,17R,35L,35R')
# noinspection SpellCheckingInspection
# https://skyvector.com/airport/0L7/Jean-Airport
K0L7 = Airfield('K0L7', 'Jean Airport',
                URCoord('35.768299', '-115.329697', '2820'),
                URFrequency('120.775;A'),
                '02L,02R,20L,20R')
# noinspection SpellCheckingInspection
# https://skyvector.com/airport/IFP/Laughlin-Bullhead-International-Airport
KIFP = Airfield('KIFP', 'Laughlin/Bullhead International Airport',
                URCoord('35.156101', '-114.559402', '656'),
                URFrequency('119.825;A'),
                '16,34')
# noinspection SpellCheckingInspection
# https://skyvector.com/airport/VGT/North-Las-Vegas-Airport
KVGT = Airfield('KVGT', 'North Las Vegas Airport',
                URCoord('36.210499', '-115.194397', '2204'),
                URFrequency('118.050;A'),
                '07,25,30L,30R,12L,12R')
# noinspection SpellCheckingInspection
# https://skyvector.com/airport/L23/Pahute-Mesa-Airstrip-Airport
KL23 = Airfield('KL23', 'Pahute Mesa Airstrip Airport',
                URCoord('37.102699', '-116.313301', '5054'),
                URFrequency('290.450;A'),
                '18,36')
# KTPH has no ATIS, using ASOS frequency instead
# noinspection SpellCheckingInspection
# https://skyvector.com/airport/TPH/Tonopah-Airport
KTPH = Airfield('KTPH', 'To-no-pah Airport',
                URCoord('38.060200', '-117.086601', '5392'),
                URFrequency('118.875;A'),
                '18,36')
# KTNX has no ATIS, using ASOS frequency instead
# noinspection SpellCheckingInspection
# https://skyvector.com/airport/TNX/Tonopah-Test-Range-Airport
KTNX = Airfield('KTNX', 'To-no-pah Test Range Airport',
                URCoord('37.794701', '-116.778603', '5546'),
                URFrequency('118.875;A'),
                '14,32')
# K1L1 has no ATIS, using ASOS frequency instead
# noinspection SpellCheckingInspection
# https://skyvector.com/airport/1L1/Lincoln-County-Airport
K1L1 = Airfield('K1L1', 'Lincoln County Airport',
                URCoord('37.787498', '-114.419998', '4811'),
                URFrequency('119.025;A'),
                '16,34')
# K67L has no ATIS, using AWOS frequency instead
# noinspection SpellCheckingInspection
# https://skyvector.com/airport/67L/Mesquite-Airport
K67L = Airfield('K67L', 'Mesquite Airport',
                URCoord('36.833000', '-114.055801', '1856'),
                URFrequency('119.425;A'),
                '02,20')
# K3Q0 has no ATIS, using ASOS frequency instead
# https://skyvector.com/airport/3Q0/Mina-Airport
K3Q0 = Airfield('K3Q0', 'Mina Airport',
                URCoord('38.379700', '-118.096298', '4549'),
                URFrequency('118.875;A'),
                '13,31')

ALL_AIRFIELDS = [UG23, UG24, UG27, UG5X, UGKO, UGKS, UGSB, UGSS, UGTB, URKG,
                 URKH, URKK, URKL, URKN, URKW, URMM, URMN, URMO, URSS, XRMF,
                 KINS, KLAS, KLSV, KXTA, KBTY, KBVU, K0L9, KHND, K0L7, KIFP,
                 KVGT, KL23, KTPH, KTNX, K1L1, K67L, K3Q0]
