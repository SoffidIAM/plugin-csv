package com.soffid.iam.sync.agent;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import au.com.bytecode.opencsv.CSVReader;
import au.com.bytecode.opencsv.CSVWriter;
import es.caib.seycon.ng.exception.InternalErrorException;

public class CSVFile {

	public String[] columns;
	public Map<String,Map<String, Object>> props;

	public CSVFile() {
		props = new HashMap<String,Map<String,Object>>();
		columns = new String[0];
	}

	public static CSVFile load (String key, String fileName) throws InternalErrorException
	{
		CSVFile file = new CSVFile();
		file.props = new HashMap<String,Map<String,Object>>();
		try
		{
			CSVReader reader = new CSVReader(new FileReader(fileName));
			file.columns = reader.readNext();
			if (file.columns != null)
			{
				int userNameColumn = 0;
				for (int i = 0; i < file.columns.length; i++)
					if (key.equals(file.columns[i]))
					{
						userNameColumn = i;
					}
				for (String[] values = reader.readNext();
						values != null;
						values = reader.readNext())
				{
					Map<String,Object> map = new HashMap<String, Object>();
					for (int i = 0; i < values.length && i < file.columns.length; i++)
					{
						map.put(file.columns[i], values[i]);
					}
					String keyValue = values[userNameColumn];
					file.props.put(keyValue, map);
				}
			}
			reader.close ();
		}
		catch (FileNotFoundException e)
		{
			file.columns = new String [] {};
		}
		catch (IOException e)
		{
			throw new InternalErrorException(e.toString());
		}
		return file;
	}
	

	
	public void save (String fileName) throws IOException
	{
		CSVWriter writer = new CSVWriter(new FileWriter(fileName));
		writer.writeNext(columns);
		for (String user: props.keySet())
		{
			String values[] = new String[columns.length];
			Map<String,Object> data = props.get(user);
			for (int i = 0; i < columns.length;i++)
			{
				Object v = data.get(columns[i]);
				values[i] = v == null? "": v.toString();
			}
			writer.writeNext(values);
		}
		writer.close();
	}
	
	public Map<String,Object> getUserData (String user)
	{
		return props.get(user);
	}

	public void addUserData (String user, Map<String, Object> data)
	{
		props.put(user, data);
		for (String s: data.keySet())
		{
			boolean found = false;
			for (String c: columns)
			{
				if (c.equals (s))
				{
					found = true;
					break;
				}
			}
			if (! found)
			{
				String newColumns[] = new String[columns.length+1];
				System.arraycopy(columns, 0, newColumns, 0, columns.length);
				newColumns [ columns.length ] = s;
				columns = newColumns;
			}
		}
	}

	public String[] getColumns() {
		return columns;
	}

	public void remove(String userName) {
		props.remove(userName);
		
	}

	public Collection<String> getAccounts() {
		return props.keySet();
	}
}
