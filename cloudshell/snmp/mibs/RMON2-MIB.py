#
# PySNMP MIB module RMON2-MIB (http://pysnmp.sf.net)
# ASN.1 source http://mibs.snmplabs.com:80/asn1/RMON2-MIB
# Produced by pysmi-0.1.3 at Mon Jul 01 11:58:37 2019
# On host ? platform ? version ? by user ?
# Using Python version 2.7.14 (v2.7.14:84471935ed, Sep 16 2017, 20:19:30) [MSC v.1500 32 bit (Intel)]
#
Integer, ObjectIdentifier, OctetString = mibBuilder.importSymbols("ASN1", "Integer", "ObjectIdentifier", "OctetString")
NamedValues, = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
ConstraintsUnion, SingleValueConstraint, ConstraintsIntersection, ValueSizeConstraint, ValueRangeConstraint = mibBuilder.importSymbols("ASN1-REFINEMENT", "ConstraintsUnion", "SingleValueConstraint", "ConstraintsIntersection", "ValueSizeConstraint", "ValueRangeConstraint")
ifIndex, = mibBuilder.importSymbols("IF-MIB", "ifIndex")
statistics, matrix, etherStatsEntry, filterEntry, hostControlEntry, filter, hosts, historyControlEntry, channelEntry, matrixControlEntry, OwnerString, history = mibBuilder.importSymbols("RMON-MIB", "statistics", "matrix", "etherStatsEntry", "filterEntry", "hostControlEntry", "filter", "hosts", "historyControlEntry", "channelEntry", "matrixControlEntry", "OwnerString", "history")
NotificationGroup, ModuleCompliance, ObjectGroup = mibBuilder.importSymbols("SNMPv2-CONF", "NotificationGroup", "ModuleCompliance", "ObjectGroup")
Integer32, MibScalar, MibTable, MibTableRow, MibTableColumn, NotificationType, MibIdentifier, mib_2, Bits, TimeTicks, Counter64, Unsigned32, ModuleIdentity, Gauge32, iso, ObjectIdentity, IpAddress, Counter32 = mibBuilder.importSymbols("SNMPv2-SMI", "Integer32", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "NotificationType", "MibIdentifier", "mib-2", "Bits", "TimeTicks", "Counter64", "Unsigned32", "ModuleIdentity", "Gauge32", "iso", "ObjectIdentity", "IpAddress", "Counter32")
DisplayString, TimeStamp, RowStatus, TextualConvention = mibBuilder.importSymbols("SNMPv2-TC", "DisplayString", "TimeStamp", "RowStatus", "TextualConvention")
rmon = ModuleIdentity((1, 3, 6, 1, 2, 1, 16))
if mibBuilder.loadTexts: rmon.setLastUpdated('9605270000Z')
protocolDir = MibIdentifier((1, 3, 6, 1, 2, 1, 16, 11))
protocolDist = MibIdentifier((1, 3, 6, 1, 2, 1, 16, 12))
addressMap = MibIdentifier((1, 3, 6, 1, 2, 1, 16, 13))
nlHost = MibIdentifier((1, 3, 6, 1, 2, 1, 16, 14))
nlMatrix = MibIdentifier((1, 3, 6, 1, 2, 1, 16, 15))
alHost = MibIdentifier((1, 3, 6, 1, 2, 1, 16, 16))
alMatrix = MibIdentifier((1, 3, 6, 1, 2, 1, 16, 17))
usrHistory = MibIdentifier((1, 3, 6, 1, 2, 1, 16, 18))
probeConfig = MibIdentifier((1, 3, 6, 1, 2, 1, 16, 19))
rmonConformance = MibIdentifier((1, 3, 6, 1, 2, 1, 16, 20))
class ZeroBasedCounter32(TextualConvention, Gauge32):
    status = 'current'

class LastCreateTime(TimeStamp):
    status = 'current'

class TimeFilter(TextualConvention, TimeTicks):
    status = 'current'

class DataSource(TextualConvention, ObjectIdentifier):
    status = 'current'

mibBuilder.exportSymbols("RMON2-MIB", addressMap=addressMap, alMatrix=alMatrix, LastCreateTime=LastCreateTime, ZeroBasedCounter32=ZeroBasedCounter32, nlHost=nlHost, nlMatrix=nlMatrix, PYSNMP_MODULE_ID=rmon, usrHistory=usrHistory, DataSource=DataSource, probeConfig=probeConfig, alHost=alHost, protocolDir=protocolDir, rmonConformance=rmonConformance, rmon=rmon, TimeFilter=TimeFilter, protocolDist=protocolDist)
