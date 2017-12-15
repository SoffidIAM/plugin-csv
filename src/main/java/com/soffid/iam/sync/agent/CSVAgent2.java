package com.soffid.iam.sync.agent;

import java.io.IOException;
import java.rmi.RemoteException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.soffid.iam.api.CustomObject;
import com.soffid.iam.sync.engine.InterfaceWrapper;
import com.soffid.iam.sync.intf.CustomObjectMgr;

import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.engine.extobj.AccountExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ValueObjectMapper;
import es.caib.seycon.ng.sync.intf.AuthoritativeChange;
import es.caib.seycon.ng.sync.intf.AuthoritativeChangeIdentifier;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;

public class CSVAgent2 extends CSVAgent implements CustomObjectMgr {

	public CSVAgent2() throws RemoteException {
	}

	public void updateCustomObject(CustomObject obj) throws RemoteException, InternalErrorException {
		ExtensibleObject soffidObject = new es.caib.seycon.ng.sync.engine.extobj.CustomExtensibleObject(obj, getServer());
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.appliesToSoffidObject(soffidObject)) 
			{
				ExtensibleObject systemObject = objectTranslator
						.generateObject(soffidObject, objectMapping);
				try {
					updateObject(systemObject);
				} catch (IOException e) {
					throw new InternalErrorException("Error updating CSV file", e);
				}
			}
		}		
	}

	public void removeCustomObject(CustomObject obj) throws RemoteException, InternalErrorException {
		ExtensibleObject soffidObject = new es.caib.seycon.ng.sync.engine.extobj.CustomExtensibleObject(obj, getServer());
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.appliesToSoffidObject(soffidObject)) 
			{
				ExtensibleObject systemObject = objectTranslator
						.generateObject(soffidObject, objectMapping);
				try {
					removeObject(systemObject);
				} catch (IOException e) {
					throw new InternalErrorException("Error updating CSV file", e);
				}
			}
		}		
	}

	int position = 0;
	public Collection<AuthoritativeChange> getChanges()
			throws InternalErrorException {
		List<AuthoritativeChange> changes = new LinkedList<AuthoritativeChange>();
		ValueObjectMapper vom = new ValueObjectMapper();
		for ( ExtensibleObjectMapping eom: objectMappings)
		{
			if (eom.getSoffidObject().equals (SoffidObjectType.OBJECT_AUTHORITATIVE_CHANGE))
			{
				String key = eom.getProperties().get("key");
				String file = eom.getProperties().get("file");
				
				if (debugEnabled)
				{
					log.info("Getting authoritative users");
				}
				CSVFile prop = CSVFile.load(key, file);
				for (String account: prop.getAccounts())
				{
					readAuthoritativeChange(changes, vom, eom, prop, account);
				}
			}
		}
		if (!changes.isEmpty())
			return changes;
		for ( ExtensibleObjectMapping eom: objectMappings)
		{
			if (eom.getSoffidObject().equals (SoffidObjectType.OBJECT_USER) ||
					eom.getSoffidObject().equals (SoffidObjectType.OBJECT_CUSTOM) ||
					eom.getSoffidObject().equals (SoffidObjectType.OBJECT_GROUP))
			{
				String key = eom.getProperties().get("key");
				String file = eom.getProperties().get("file");
				String backup = eom.getProperties().get("backup");
				
				if (debugEnabled)
				{
					log.info("Getting authoritative users");
				}
				CSVFile prop = CSVFile.load(key, file);
				for (String account: prop.getAccounts())
				{
					if (eom.getSoffidObject().equals (SoffidObjectType.OBJECT_USER))
						readUser(changes, vom, eom, prop, null, account);
					if (eom.getSoffidObject().equals (SoffidObjectType.OBJECT_GROUP))
						readGroup(changes, vom, eom, prop, null, account);
					if (eom.getSoffidObject().equals (SoffidObjectType.OBJECT_CUSTOM))
						readCustomObject(changes, vom, eom, prop, null, account);
				}
				if ("true".equals(backup))
				{
					try {
						prop.save(file+"-last");
						prop.save(file+"-"+new SimpleDateFormat("yyyy-MM-dd-HH:MM").format(new Date()));
					} catch (IOException e) {
						throw new InternalErrorException("Error storing backup file ", e);
					}
				}
			}
		}
		return changes;
	}

	protected AuthoritativeChange readGroup(List<AuthoritativeChange> changes,
			ValueObjectMapper vom, ExtensibleObjectMapping eom, CSVFile prop,
			CSVFile backProp, String account) throws InternalErrorException {
		Map<String, Object> identity = prop.getUserData(account);
		
		ExtensibleObject eo = new ExtensibleObject();
		eo.setObjectType(eom.getSystemObject());
		eo.putAll(identity);
		if (debugEnabled)
		{
			debugObject("Got raw group", eo, "   ");
		}
		ExtensibleObject input = objectTranslator.parseInputObject(eo, eom);
		if (input != null)
		{
			if (debugEnabled)
			{
				debugObject("Got soffid group", eo, "   ");
			}
			Grup g = vom.parseGroup(input);
			if (g != null)
			{
				AuthoritativeChange ch = new AuthoritativeChange();
				ch.setId(new AuthoritativeChangeIdentifier());
				ch.getId().setChangeId(g.getCodi());
				ch.setGroup(g);
				changes.add(ch);
				return ch;
			}
		}
		return null;
	}
	
	protected AuthoritativeChange readCustomObject(List<AuthoritativeChange> changes,
			ValueObjectMapper vom, ExtensibleObjectMapping eom, CSVFile prop,
			CSVFile backProp, String account) throws InternalErrorException {
		Map<String, Object> identity = prop.getUserData(account);
		
		ExtensibleObject eo = new ExtensibleObject();
		eo.setObjectType(eom.getSystemObject());
		eo.putAll(identity);
		if (debugEnabled)
		{
			debugObject("Got raw object", eo, "   ");
		}
		ExtensibleObject input = objectTranslator.parseInputObject(eo, eom);
		if (input != null)
		{
			if (debugEnabled)
			{
				debugObject("Got soffid custom object", eo, "   ");
			}
			CustomObject g = vom.parseCustomObject(eo);
			if (g != null)
			{
				AuthoritativeChange ch = new AuthoritativeChange();
				ch.setId(new AuthoritativeChangeIdentifier());
				ch.getId().setChangeId(g.getName());
				ch.setObject(g);
				changes.add(ch);
				return ch;
			}
		}
		return null;
	}

	@Override
	public ExtensibleObject getNativeObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		ValueObjectMapper vom = new ValueObjectMapper();
		ExtensibleObject sample = getExtensibleObject(type, object1, object2);
		// For each mapping
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.appliesToSoffidObject(sample)) {
				String key = objectMapping.getProperties().get("key");
				String file = objectMapping.getProperties().get("file");
				String keyValue = vom.toSingleString(
						objectTranslator
						.generateAttribute(key, sample,  objectMapping));
				CSVFile prop = CSVFile.load(key, file);
				Map<String, Object> identity = prop.getUserData(keyValue);

				ExtensibleObject eo = new ExtensibleObject();
				eo.setObjectType(objectMapping.getSystemObject());
				eo.putAll(identity);
				if (debugEnabled)
				{
					debugObject("Got raw identity", eo, "");
				}
				return eo;
			}
		}

		return null;
	}

	@Override
	public ExtensibleObject getSoffidObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		ValueObjectMapper vom = new ValueObjectMapper();
		ExtensibleObject sample = getExtensibleObject(type, object1, object2);
		// For each mapping
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.appliesToSoffidObject(sample)) {
				ExtensibleObject translatedSample = objectTranslator
						.generateObject(sample, objectMapping);

				String key = objectMapping.getProperties().get("key");
				String file = objectMapping.getProperties().get("file");
				String keyValue = vom.toSingleString(
						objectTranslator
						.generateAttribute(key, sample,  objectMapping));
				CSVFile prop = CSVFile.load(key, file);
				Map<String, Object> identity = prop.getUserData(keyValue);

				ExtensibleObject eo = new ExtensibleObject();
				eo.setObjectType(objectMapping.getSystemObject());
				eo.putAll(identity);
				if (debugEnabled)
				{
					debugObject("Got raw identity", eo, "");
				}
				ExtensibleObject input = objectTranslator.parseInputObject(eo, objectMapping);
				if (input != null)
					return input;
			}
		}

		return null;
	}


}
