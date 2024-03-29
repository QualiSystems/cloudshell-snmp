#
# PySNMP MIB module PYSNMP-USM-MIB (http://pysnmp.sf.net)
# ASN.1 source file:///Users/ilya/src/py/pysnmp/docs/mibs/PYSNMP-USM-MIB.txt
# Produced by pysmi-0.0.5 at Sat Sep 19 16:26:08 2015
# On host grommit.local platform Darwin version 14.4.0 by user ilya
# Using Python version 2.7.6 (default, Sep  9 2014, 15:04:36) 
#
( Integer, ObjectIdentifier, OctetString, ) = mibBuilder.importSymbols("ASN1", "Integer", "ObjectIdentifier", "OctetString")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ConstraintsUnion, SingleValueConstraint, ConstraintsIntersection, ValueSizeConstraint, ValueRangeConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ConstraintsUnion", "SingleValueConstraint", "ConstraintsIntersection", "ValueSizeConstraint", "ValueRangeConstraint")
( pysnmpModuleIDs, ) = mibBuilder.importSymbols("PYSNMP-MIB", "pysnmpModuleIDs")
( SnmpAdminString, ) = mibBuilder.importSymbols("SNMP-FRAMEWORK-MIB", "SnmpAdminString")
( usmUserEntry, ) = mibBuilder.importSymbols("SNMP-USER-BASED-SM-MIB", "usmUserEntry")
( NotificationGroup, ModuleCompliance, ) = mibBuilder.importSymbols("SNMPv2-CONF", "NotificationGroup", "ModuleCompliance")
( Integer32, MibScalar, MibTable, MibTableRow, MibTableColumn, NotificationType, MibIdentifier, IpAddress, TimeTicks, Counter64, Unsigned32, ModuleIdentity, Gauge32, iso, ObjectIdentity, Bits, Counter32, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Integer32", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "NotificationType", "MibIdentifier", "IpAddress", "TimeTicks", "Counter64", "Unsigned32", "ModuleIdentity", "Gauge32", "iso", "ObjectIdentity", "Bits", "Counter32")
( DisplayString, RowStatus, TextualConvention, ) = mibBuilder.importSymbols("SNMPv2-TC", "DisplayString", "RowStatus", "TextualConvention")
pysnmpUsmMIB = ModuleIdentity((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1)).setRevisions(("2005-05-14 00:00",))
if mibBuilder.loadTexts: pysnmpUsmMIB.setLastUpdated('200505140000Z')
if mibBuilder.loadTexts: pysnmpUsmMIB.setOrganization('The PySNMP project')
if mibBuilder.loadTexts: pysnmpUsmMIB.setContactInfo('E-mail:     ilya@glas.net\n                  Subscribe:  pysnmp-users-request@lists.sourceforge.net')
if mibBuilder.loadTexts: pysnmpUsmMIB.setDescription('This MIB module defines objects specific to User\n             Security Model (USM) implementation at PySNMP.')
pysnmpUsmMIBObjects = MibIdentifier((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1))
pysnmpUsmMIBConformance = MibIdentifier((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 2))
pysnmpUsmCfg = MibIdentifier((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 1))
pysnmpUsmDiscoverable = MibScalar((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 1, 1), Integer32().subtype(subtypeSpec=SingleValueConstraint(0, 1,)).clone(namedValues=NamedValues(("notDiscoverable", 0), ("discoverable", 1),)).clone('discoverable')).setMaxAccess("readwrite")
if mibBuilder.loadTexts: pysnmpUsmDiscoverable.setDescription('Whether SNMP engine would support its discovery by\n                 responding to unknown clients.')
pysnmpUsmDiscovery = MibScalar((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 1, 2), Integer32().subtype(subtypeSpec=SingleValueConstraint(0, 1,)).clone(namedValues=NamedValues(("doNotDiscover", 0), ("doDiscover", 1),)).clone('doDiscover')).setMaxAccess("readwrite")
if mibBuilder.loadTexts: pysnmpUsmDiscovery.setDescription('Whether SNMP engine would try to figure out the EngineIDs\n                 of its peers by sending discover requests.')
pysnmpUsmUser = MibIdentifier((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 3))
pysnmpUsmSecretTable = MibTable((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 2), )
if mibBuilder.loadTexts: pysnmpUsmSecretTable.setDescription("The table of USM users passphrases configured in the SNMP \n         engine's Local Configuration Datastore (LCD).")
pysnmpUsmSecretEntry = MibTableRow((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 2, 1), ).setIndexNames((1, "PYSNMP-USM-MIB", "pysnmpUsmSecretUserName"))
if mibBuilder.loadTexts: pysnmpUsmSecretEntry.setDescription('Information about a particular USM user credentials.')
pysnmpUsmSecretUserName = MibTableColumn((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 2, 1, 1), SnmpAdminString().subtype(subtypeSpec=ValueSizeConstraint(1,32)))
if mibBuilder.loadTexts: pysnmpUsmSecretUserName.setDescription('The username string for which a row in this table\n         represents a configuration.')
pysnmpUsmSecretAuthKey = MibTableColumn((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 2, 1, 2), OctetString().subtype(subtypeSpec=ValueSizeConstraint(8,65535)))
if mibBuilder.loadTexts: pysnmpUsmSecretAuthKey.setDescription("User's authentication passphrase used for localized key generation.")
pysnmpUsmSecretPrivKey = MibTableColumn((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 2, 1, 3), OctetString().subtype(subtypeSpec=ValueSizeConstraint(8,65535)))
if mibBuilder.loadTexts: pysnmpUsmSecretPrivKey.setDescription("User's encryption passphrase used for localized key generation.")
pysnmpUsmSecretStatus = MibTableColumn((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 2, 1, 4), RowStatus()).setMaxAccess("readcreate")
if mibBuilder.loadTexts: pysnmpUsmSecretStatus.setDescription('Table status')
pysnmpUsmKeyTable = MibTable((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 3), )
if mibBuilder.loadTexts: pysnmpUsmKeyTable.setDescription("The table of USM users localized keys configured in the \n         SNMP engine's Local Configuration Datastore (LCD).")
pysnmpUsmKeyEntry = MibTableRow((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 3, 1), )
usmUserEntry.registerAugmentions(("PYSNMP-USM-MIB", "pysnmpUsmKeyEntry"))
pysnmpUsmKeyEntry.setIndexNames(*usmUserEntry.getIndexNames())
if mibBuilder.loadTexts: pysnmpUsmKeyEntry.setDescription('Information about a particular USM user credentials.')
pysnmpUsmKeyAuthLocalized = MibTableColumn((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 3, 1, 1), OctetString().subtype(subtypeSpec=ValueSizeConstraint(8,32)))
if mibBuilder.loadTexts: pysnmpUsmKeyAuthLocalized.setDescription("User's localized key used for authentication.")
pysnmpUsmKeyPrivLocalized = MibTableColumn((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 3, 1, 2), OctetString().subtype(subtypeSpec=ValueSizeConstraint(8,32)))
if mibBuilder.loadTexts: pysnmpUsmKeyPrivLocalized.setDescription("User's localized key used for encryption.")
pysnmpUsmKeyAuth = MibTableColumn((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 3, 1, 3), OctetString().subtype(subtypeSpec=ValueSizeConstraint(8,32)))
if mibBuilder.loadTexts: pysnmpUsmKeyAuth.setDescription("User's non-localized key used for authentication.")
pysnmpUsmKeyPriv = MibTableColumn((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 1, 3, 1, 4), OctetString().subtype(subtypeSpec=ValueSizeConstraint(8,32)))
if mibBuilder.loadTexts: pysnmpUsmKeyPriv.setDescription("User's non-localized key used for encryption.")
pysnmpUsmMIBCompliances = MibIdentifier((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 2, 1))
pysnmpUsmMIBGroups = MibIdentifier((1, 3, 6, 1, 4, 1, 20408, 3, 1, 1, 2, 2))
mibBuilder.exportSymbols("PYSNMP-USM-MIB", pysnmpUsmCfg=pysnmpUsmCfg, PYSNMP_MODULE_ID=pysnmpUsmMIB, pysnmpUsmKeyAuthLocalized=pysnmpUsmKeyAuthLocalized, pysnmpUsmKeyTable=pysnmpUsmKeyTable, pysnmpUsmDiscovery=pysnmpUsmDiscovery, pysnmpUsmMIBCompliances=pysnmpUsmMIBCompliances, pysnmpUsmSecretAuthKey=pysnmpUsmSecretAuthKey, pysnmpUsmSecretStatus=pysnmpUsmSecretStatus, pysnmpUsmKeyPrivLocalized=pysnmpUsmKeyPrivLocalized, pysnmpUsmKeyEntry=pysnmpUsmKeyEntry, pysnmpUsmKeyPriv=pysnmpUsmKeyPriv, pysnmpUsmSecretTable=pysnmpUsmSecretTable, pysnmpUsmUser=pysnmpUsmUser, pysnmpUsmMIBGroups=pysnmpUsmMIBGroups, pysnmpUsmMIB=pysnmpUsmMIB, pysnmpUsmSecretEntry=pysnmpUsmSecretEntry, pysnmpUsmDiscoverable=pysnmpUsmDiscoverable, pysnmpUsmMIBObjects=pysnmpUsmMIBObjects, pysnmpUsmSecretUserName=pysnmpUsmSecretUserName, pysnmpUsmSecretPrivKey=pysnmpUsmSecretPrivKey, pysnmpUsmKeyAuth=pysnmpUsmKeyAuth, pysnmpUsmMIBConformance=pysnmpUsmMIBConformance)
