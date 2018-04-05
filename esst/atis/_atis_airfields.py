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
                '07,25')
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

ALL_AIRFIELDS = [UG23, UG24, UG27, UG5X, UGKO, UGKS, UGSB, UGSS, UGTB, URKG,
                 URKH, URKK, URKL, URKN, URKW, URMM, URMN, URMO, URSS, XRMF]
