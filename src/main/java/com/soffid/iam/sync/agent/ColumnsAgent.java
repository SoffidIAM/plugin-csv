package com.soffid.iam.sync.agent;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.rmi.RemoteException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
import es.caib.seycon.ng.sync.intf.AuthoritativeIdentitySource2;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMgr;
import es.caib.seycon.ng.sync.intf.ReconcileMgr2;
import es.caib.seycon.ng.sync.intf.UserMgr;
import es.caib.seycon.util.Base64.InputStream;

public class ColumnsAgent extends Agent implements AuthoritativeIdentitySource2, ExtensibleObjectMgr {
	boolean debugEnabled = true;
	ObjectTranslator objectTranslator = null;
	private Collection<ExtensibleObjectMapping> objectMappings;
	private String encoding;
	private ValueObjectMapper vom;

	public ColumnsAgent() throws RemoteException {
	}

	public void init() {
		debugEnabled = "true".equals(getDispatcher().getParam0());
		encoding = getDispatcher().getParam1();
		if (encoding == null || encoding.trim().isEmpty())
			encoding = Charset.defaultCharset().toString();
	}

	public void configureMappings(Collection<ExtensibleObjectMapping> objects)
			throws RemoteException, InternalErrorException {
		this.objectMappings = objects;
		objectTranslator = new ObjectTranslator(getDispatcher(), getServer(),
				objectMappings);
		vom = new ValueObjectMapper();

	}

	private AuthoritativeChange readUser(ExtensibleObjectMapping eom, int rowNumber, byte[] line) throws InternalErrorException {
		ExtensibleObject eo = new ExtensibleObject();
		eo.setObjectType(eom.getSystemObject());

		Pattern p = Pattern.compile("([0-9]+)\\b*-\\b*([0-9]+)");
		
		for (String key : eom.getProperties().keySet())
		{
			String column = eom.getProperties().get(key);
			Matcher m = p.matcher(key);
			
			if (m.matches())
			{
				int from = Integer.decode(m.group(1)).intValue();
				int to = Integer.decode(m.group(2)).intValue();
				if (from < 1)
					throw new InternalErrorException("Error in range "+key+"->"+column+". Start column cannot be less than 1");
				if (from > to)
					throw new InternalErrorException("Error in range "+key+"->"+column+". Start column ("+from+") cannot be after end column ("+to+")");
				String value;
				try {
					if (to > line.length)
						throw new InternalErrorException("Error reading line "+rowNumber+": missing column "+column);
					value = new String (line, from - 1, to - from + 1, encoding).trim();
				} catch (UnsupportedEncodingException e) {
					throw new InternalErrorException("Error decoding from charset "+encoding);
				}
				eo.put(column, value);
			}
		}

		if (debugEnabled)
		{
			debugObject("Got raw identity", eo, "   ");
		}
		
		ExtensibleObject input = objectTranslator.parseInputObject(eo, eom);
		if (input != null)
		{
			if (debugEnabled)
			{
				debugObject("Got soffid identity", input, "   ");
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
				List<Map<String,Object>> groups = (List<Map<String, Object>>) input.getAttribute("secondaryGroups");
				if (groups != null)
				{
					LinkedList<String> gr2 = new LinkedList<String>();
					for (Map<String, Object> grMap: groups)
					{
						String name = (String) grMap.get("name");
						if (name != null)
							gr2.add (name);
					}
					ch.setGroups(new HashSet<String>(gr2));
				}
				return ch;
			}
		}
		return null;
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

	int lastRow = 0;
	long loadingFile;
	boolean eof = false;
	boolean end = false;
	HashSet<String> loadedUsers = new HashSet<String>();
	
	@SuppressWarnings("resource")
	public Collection<AuthoritativeChange> getChanges(String lastChange)
			throws InternalErrorException {
		try {
			List<AuthoritativeChange> changes = new LinkedList<AuthoritativeChange>();
			ValueObjectMapper vom = new ValueObjectMapper();
			for ( ExtensibleObjectMapping eom: objectMappings)
			{
				if (eom.getSoffidObject().equals (SoffidObjectType.OBJECT_USER) || 
						eom.getSoffidObject().equals (SoffidObjectType.OBJECT_AUTHORITATIVE_CHANGE))
				{
					String file = eom.getProperties().get("file");
					if (file == null)
						throw new InternalErrorException("Missing file property for "+eom.getSystemObject()+" object type");
					String rs = eom.getProperties().get("recordSize");
					if (rs == null)
						throw new InternalErrorException("Missing file property for "+eom.getSystemObject()+" object type");
					int recordSize = Integer.parseInt(rs);
					
					File f = new File (file);
					
					if (loadingFile == 0)
						loadingFile = f.lastModified();
					if (loadingFile != f.lastModified())
						throw new InternalErrorException("File "+file+" has been modified during load process");
					long lastCommitedChange = lastChange == null ? 0 : Long.decode(lastChange);
					// Test if this file has already been loaded
					if (lastCommitedChange >= f.lastModified())
					{
						return null;
					}
						
					byte [] row = new byte [recordSize];
					if ( !eof )
					{
						FileInputStream input = new FileInputStream(f);
						for (int i = 0; i < lastRow; i++)
						{
							input.read(row);
						}
						while (changes.size() < 100)
						{
							if (input.read(row) < 0)
							{
								eof = true;
								lastRow = 0;
								break;
							} else {
								AuthoritativeChange ch = readUser(eom, lastRow+1, row);
								if (ch != null && ch.getUser() != null)
								{
									changes.add(ch);
									if (ch.getUser().getCodi() != null)
									{
										loadedUsers.add (ch.getUser().getCodi());
									}
								}
								lastRow ++;
							}
						}
						input.close();
					}
					
					if (eof && !end  && changes.size() < 100) {
						File back = new File ( file+"."+lastChange );
						if (back.canRead())
						{
							FileInputStream input = new FileInputStream(back);
							// Skip already loaded rows
							for (int i = 0; i < lastRow; i++)
							{
								input.read(row);
							}
							// Now, read up to 100 rowso
							while (changes.size() < 100)
							{
								if (input.read(row) < 0)
								{
									end = true;
									break;
								} else {
									AuthoritativeChange ch = readUser(eom, lastRow + 1, row);
									if (ch != null && ch.getUser() != null &&
										ch.getUser().getCodi() != null && 
										! loadedUsers.contains(ch.getUser().getCodi()))
									{
										ch.getUser().setActiu(false);
										changes.add(ch);
									}
									lastRow ++;
								}
							}
							input.close();
						}
						else
							end = true;
						
						if (end)
						{
							copyFile (f, new File ( file+"."+loadingFile));
							copyFile (f, new File ( file+".latest"));
						}
					}
					return changes;
				}
			}
			return null;
		} catch ( IOException e) {
			throw new InternalErrorException("Input/output error.", e);
		}
	}
		

	private void copyFile(File src, File target) throws IOException 
	{
		FileInputStream in = new FileInputStream(src);
		FileOutputStream out = new FileOutputStream(target);
		int read;
		while ( (read = in.read()) >= 0)
			out.write(read);
		in.close();
		out.close();
	}

	public String getNextChange() throws InternalErrorException {
		return ""+loadingFile;
	}

	public boolean hasMoreData() throws InternalErrorException {
		return !end;
	}


}
