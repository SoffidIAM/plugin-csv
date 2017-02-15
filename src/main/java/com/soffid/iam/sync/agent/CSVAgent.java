package com.soffid.iam.sync.agent;

import java.io.IOException;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.engine.extobj.AccountExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ObjectTranslator;
import es.caib.seycon.ng.sync.engine.extobj.UserExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ValueObjectMapper;
import es.caib.seycon.ng.sync.intf.AuthoritativeChange;
import es.caib.seycon.ng.sync.intf.AuthoritativeChangeIdentifier;
import es.caib.seycon.ng.sync.intf.AuthoritativeIdentitySource;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMgr;
import es.caib.seycon.ng.sync.intf.ReconcileMgr2;
import es.caib.seycon.ng.sync.intf.UserMgr;

public class CSVAgent extends Agent implements UserMgr, ReconcileMgr2,
		AuthoritativeIdentitySource, ExtensibleObjectMgr {
	boolean debugEnabled = true;
	ObjectTranslator objectTranslator = null;
	private Collection<ExtensibleObjectMapping> objectMappings;

	public CSVAgent() throws RemoteException {
	}

	public void init() {
		debugEnabled = "true".equals(getDispatcher().getParam5());
	}

	public void configureMappings(Collection<ExtensibleObjectMapping> objects)
			throws RemoteException, InternalErrorException {
		this.objectMappings = objects;
		objectTranslator = new ObjectTranslator(getDispatcher(), getServer(),
				objectMappings);

	}

	private void updateObject(ExtensibleObject systemObject) throws InternalErrorException, IOException {
		ValueObjectMapper vom = new ValueObjectMapper();
		for ( ExtensibleObjectMapping eom: objectMappings)
		{
			if (eom.getSystemObject().equals(systemObject.getObjectType()))
			{
				String key = eom.getProperties().get("key");
				String file = eom.getProperties().get("file");
				
				if (debugEnabled)
				{
					debugObject("Dumping object on file "+file, systemObject, "   ");
				}
				System.out.println(getDispatcher().getCodi() + ": UpdateUser "
						+ systemObject.get(key));
				CSVFile prop = CSVFile.load(key, file);
				String keyValue = vom.toSingleString(systemObject.get(key));
				prop.addUserData(keyValue, systemObject);
				prop.save(file);
			}
		}
	}

	private void removeObject(ExtensibleObject systemObject) throws InternalErrorException, IOException {
		ValueObjectMapper vom = new ValueObjectMapper();
		for ( ExtensibleObjectMapping eom: objectMappings)
		{
			if (eom.getSystemObject().equals(systemObject.getObjectType()))
			{
				String key = eom.getProperties().get("key");
				String file = eom.getProperties().get("file");
				
				if (debugEnabled)
				{
					debugObject("Dumping object on file "+file, systemObject, "   ");
				}
				System.out.println(getDispatcher().getCodi() + ": UpdateUser "
						+ systemObject.get(key));
				CSVFile prop = CSVFile.load(key, file);
				String keyValue = vom.toSingleString(systemObject.get(key));
				prop.remove(keyValue);;
				prop.save(file);
			}
		}
	}

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
					Map<String, Object> identity = prop.getUserData(account);
					ExtensibleObject eo = new ExtensibleObject();
					eo.setObjectType(eom.getSystemObject());
					eo.putAll(identity);
					if (debugEnabled)
					{
						debugObject("Got raw identity", eo, "   ");
					}
					ExtensibleObject input = objectTranslator.parseInputObject(eo, eom);
					if (input != null)
					{
						if (debugEnabled)
						{
							debugObject("Got soffid identity", eo, "   ");
						}
						AuthoritativeChange change = vom.parseAuthoritativeChange(input);
						if (change != null)
							changes.add(change);
					}
				}
			}
		}
		if (!changes.isEmpty())
			return changes;
		for ( ExtensibleObjectMapping eom: objectMappings)
		{
			if (eom.getSoffidObject().equals (SoffidObjectType.OBJECT_USER))
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
					Map<String, Object> identity = prop.getUserData(account);
					ExtensibleObject eo = new ExtensibleObject();
					eo.setObjectType(eom.getSystemObject());
					eo.putAll(identity);
					if (debugEnabled)
					{
						debugObject("Got raw identity", eo, "   ");
					}
					ExtensibleObject input = objectTranslator.parseInputObject(eo, eom);
					if (input != null)
					{
						if (debugEnabled)
						{
							debugObject("Got soffid identity", eo, "   ");
						}
						Usuari usuari = vom.parseUsuari(input);
						if (usuari != null)
						{
							AuthoritativeChange ch = new AuthoritativeChange();
							ch.setId(new AuthoritativeChangeIdentifier());
							ch.getId().setChangeId(usuari.getCodi());
							ch.setUser(usuari);
							Map<String,Object> attributes = (Map<String, Object>) input.getAttribute("attributes");
							ch.setAttributes(attributes);
							changes.add(ch);
						}
					}
				}
			}
		}
		return changes;
	}

	public void commitChange(AuthoritativeChangeIdentifier id)
			throws InternalErrorException {

	}

	public void updateUser(String accountName, String description)
			throws RemoteException, InternalErrorException {
		Account acc = getServer().getAccountInfo(accountName, getCodi());
		ExtensibleObject soffidObject = new AccountExtensibleObject(acc,
				getServer());
		String password;
		password = getAccountPassword(accountName);
		soffidObject.put("password", password);

		// First update user
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ACCOUNT)) {
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


	public void removeUser(String accountName) throws RemoteException,
			InternalErrorException {
		Account acc = new Account();
		acc.setName(accountName);
		acc.setDescription(null);
		acc.setDisabled(true);
		acc.setDispatcher(getCodi());
		ExtensibleObject soffidObject = new AccountExtensibleObject(acc,
				getServer());

		// First update role
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ACCOUNT)) {
				ExtensibleObject sqlobject = objectTranslator.generateObject(
						soffidObject, objectMapping);
				try {
					removeObject(sqlobject);
				} catch (IOException e) {
					throw new InternalErrorException("Error updating CSV file", e);
				}
			}
		}
	}

	public void updateUserPassword(String accountName, Usuari userData,
			Password password, boolean mustchange) throws RemoteException,
			InternalErrorException {

		Account acc = getServer().getAccountInfo(accountName, getDispatcher().getCodi());
		ExtensibleObject soffidObject = new UserExtensibleObject(acc, userData,
				getServer());

		soffidObject.put("password", password.getPassword());
		soffidObject.put("mustChangePassword", mustchange);

		// First update role
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ACCOUNT)
					&& userData == null
					|| objectMapping.getSoffidObject().equals(
							SoffidObjectType.OBJECT_USER) && userData != null) {

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

	public boolean validateUserPassword(String accountName, Password password)
			throws RemoteException, InternalErrorException {
		return false;
	}

	void debugObject(String msg, Map<String, Object> obj, String indent) {
		if (debugEnabled) {
			if (indent == null)
				indent = "";
			if (msg != null)
				log.info(indent + msg);
			for (String attribute : obj.keySet()) {
				Object subObj = obj.get(attribute);
				if (subObj == null) {
					log.info(indent + attribute.toString() + ": null");
				} else if (subObj instanceof Map) {
					log.info(indent + attribute.toString() + ": Object {");
					debugObject(null, (Map<String, Object>) subObj, indent
							+ "   ");
					log.info(indent + "}");
				} else {
					log.info(indent + attribute.toString() + ": "
							+ subObj.toString());
				}
			}
		}
	}

	public void updateUser(String accountName, Usuari userData)
			throws RemoteException, InternalErrorException {
		Account acc = new Account();
		acc.setName(accountName);
		acc.setDescription(userData.getFullName());
		acc.setDispatcher(getCodi());
		ExtensibleObject soffidObject = new UserExtensibleObject(acc, userData,
				getServer());

		String password;
		password = getAccountPassword(accountName);
		soffidObject.put("password", password);
		// First update role
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_USER)) {
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

	private String getAccountPassword(String accountName)
			throws InternalErrorException {
		Password p = getServer().getAccountPassword(accountName, getCodi());
		if (p == null) {
			p = getServer().generateFakePassword(accountName, getCodi());
		}
		return p.getPassword();
	}

	public Account getAccountInfo(String userAccount) throws RemoteException,
			InternalErrorException {
		ValueObjectMapper vom = new ValueObjectMapper();
		Account acc = new Account();
		acc.setName(userAccount);
		acc.setDispatcher(getCodi());
		ExtensibleObject sample = new AccountExtensibleObject(acc, getServer());
		// For each mapping
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ACCOUNT)) {
				
				ExtensibleObject translatedSample = objectTranslator
						.generateObject(sample, objectMapping);

				String key = objectMapping.getProperties().get("key");
				String file = objectMapping.getProperties().get("file");
				if (debugEnabled)
				{
					log.info("Getting account info for "+userAccount);
				}
				String keyValue = vom.toSingleString(
						objectTranslator
						.generateAttribute(key, sample,  objectMapping));
				if (debugEnabled)
				{
					log.info("Key column: "+keyValue);
				}
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
				{
					if (debugEnabled)
					{
						debugObject("Got soffid identity", eo, "");
					}
					Account account = vom.parseAccount(input);
					if (account != null)
						return account;
				}
			}
		}

		return null;
	}

	public List<String> getAccountsList() throws RemoteException,
			InternalErrorException {

		ValueObjectMapper vom = new ValueObjectMapper();
		ExtensibleObject sample = new ExtensibleObject();
		List<String> accountNames = new LinkedList<String>();
		if (debugEnabled)
			log.info ("Getting account list");
		// For each mapping
		for (ExtensibleObjectMapping objectMapping : objectMappings) {
			if (objectMapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ACCOUNT)) {
				
				String key = objectMapping.getProperties().get("key");
				String file = objectMapping.getProperties().get("file");
				CSVFile prop = CSVFile.load(key, file);
				for (String keyValue: prop.getAccounts())
				{
					Map<String, Object> identity = prop.getUserData(keyValue);
					ExtensibleObject eo = new ExtensibleObject();
					eo.setObjectType(objectMapping.getSystemObject());
					eo.putAll(identity);
					
					if (debugEnabled)
					{
						debugObject("Got raw identity", eo, "");
					}
					String accountName = vom.toSingleString(
							objectTranslator
							.parseInputAttribute("accountName", eo, objectMapping));
					if (debugEnabled)
					{
						log.info ("Account name: "+accountName);
					}
					if (accountName != null)
						accountNames.add(accountName);
				}
			}
		}

		return accountNames;
	}

	public List<RolGrant> getAccountGrants(String arg0) throws RemoteException,
			InternalErrorException {
		return new LinkedList<RolGrant>();
	}

	public Rol getRoleFullInfo(String arg0) throws RemoteException,
			InternalErrorException {
		return null;
	}

	public List<String> getRolesList() throws RemoteException,
			InternalErrorException {
		return new LinkedList<String>();
	}


}
