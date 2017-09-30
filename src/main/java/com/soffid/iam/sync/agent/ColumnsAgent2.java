package com.soffid.iam.sync.agent;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.soffid.iam.api.CustomObject;
import com.soffid.iam.sync.intf.CustomObjectMgr;

import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.engine.extobj.ValueObjectMapper;
import es.caib.seycon.ng.sync.intf.AuthoritativeChange;
import es.caib.seycon.ng.sync.intf.AuthoritativeChangeIdentifier;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;

public class ColumnsAgent2 extends ColumnsAgent implements CustomObjectMgr {

	public ColumnsAgent2() throws RemoteException {
	}

	public void updateCustomObject(CustomObject obj) throws RemoteException, InternalErrorException {
		
	}

	public void removeCustomObject(CustomObject obj) throws RemoteException, InternalErrorException {
	}

	@SuppressWarnings("resource")
	public Collection<AuthoritativeChange> getChanges(String lastChange)
			throws InternalErrorException {
		try {
			List<AuthoritativeChange> changes = new LinkedList<AuthoritativeChange>();
			ValueObjectMapper vom = new ValueObjectMapper();
			for ( ExtensibleObjectMapping eom: objectMappings)
			{
				if (eom.getSoffidObject().equals (SoffidObjectType.OBJECT_USER) || 
						eom.getSoffidObject().equals (SoffidObjectType.OBJECT_AUTHORITATIVE_CHANGE) ||
						eom.getSoffidObject().equals (SoffidObjectType.OBJECT_CUSTOM))
				{
					readChanges(lastChange, eom, changes);
				}
			}
			return changes;
		} catch ( IOException e) {
			throw new InternalErrorException("Input/output error.", e);
		}
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


		

	public ExtensibleObject getNativeObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		try {
			ValueObjectMapper vom = new ValueObjectMapper();
			for ( ExtensibleObjectMapping eom: objectMappings)
			{
				if (eom.getSoffidObject().toString().equals (type.toString()))
				{
					String file = eom.getProperties().get("file");
					if (file == null)
						throw new InternalErrorException("Missing file property for "+eom.getSystemObject()+" object type");
					String rs = eom.getProperties().get("recordSize");
					if (rs == null)
						throw new InternalErrorException("Missing file property for "+eom.getSystemObject()+" object type");
					int recordSize = Integer.parseInt(rs);
					
					File f = new File (file);
					
					byte [] row = new byte [recordSize];
					FileInputStream input = new FileInputStream(f);
					int rowNumber = 0;
					while (input.read(row) > 0)
					{
						rowNumber ++;
						ExtensibleObject eo = readNativeObject(eom, rowNumber, row);
						ExtensibleObject eo2 = objectTranslator.parseInputObject(eo, eom);
						if (eo2 != null)
						{
							AuthoritativeChange ch = vom.parseAuthoritativeChange(eo2); 
							if (ch != null && ch.getUser() != null && ch.getUser().getCodi().equals(object1))
							{
								input.close();
								return eo;
							}
							if (ch != null && ch.getGroup() != null && ch.getGroup().getCodi().equals(object1))
							{
								input.close();
								return eo;
							}
							if (ch != null && ch.getObject() != null && ch.getObject().getName().equals(object2)
									&& ch.getObject().getType().equals(object1))
							{
								input.close();
								return eo;
							}
						}
					}
					input.close();
				}
			}
			return null;
		} catch ( IOException e) {
			throw new InternalErrorException("Input/output error.", e);
		}
	}

	public ExtensibleObject getSoffidObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		try {
			ValueObjectMapper vom = new ValueObjectMapper();
			for ( ExtensibleObjectMapping eom: objectMappings)
			{
				if (eom.getSoffidObject().toString().equals (type.toString()))
				{
					String file = eom.getProperties().get("file");
					if (file == null)
						throw new InternalErrorException("Missing file property for "+eom.getSystemObject()+" object type");
					String rs = eom.getProperties().get("recordSize");
					if (rs == null)
						throw new InternalErrorException("Missing file property for "+eom.getSystemObject()+" object type");
					int recordSize = Integer.parseInt(rs);
					
					File f = new File (file);
					
					byte [] row = new byte [recordSize];
					FileInputStream input = new FileInputStream(f);
					int rowNumber = 0;
					while (input.read(row) > 0)
					{
						rowNumber ++;
						ExtensibleObject eo = readLine(eom, rowNumber, row);
						AuthoritativeChange ch = vom.parseAuthoritativeChange(eo); 
						if (ch != null && ch.getUser() != null && ch.getUser().getCodi().equals(object1))
						{
							input.close();
							return eo;
						}
						if (ch != null && ch.getGroup() != null && ch.getGroup().getCodi().equals(object1))
						{
							input.close();
							return eo;
						}
						if (ch != null && ch.getObject() != null && ch.getObject().getName().equals(object2)
								&& ch.getObject().getType().equals(object1))
						{
							input.close();
							return eo;
						}
					}
					input.close();
				}
			}
			return null;
		} catch ( IOException e) {
			throw new InternalErrorException("Input/output error.", e);
		}
	}

}
