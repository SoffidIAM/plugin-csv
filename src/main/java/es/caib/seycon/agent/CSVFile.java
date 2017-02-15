package es.caib.seycon.agent;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
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
	public Map<String,Map<String, String>> props;

	public CSVFile() {
	}

	public static CSVFile load (String fileName) throws InternalErrorException
	{
		CSVFile file = new CSVFile();
		file.props = new HashMap<String,Map<String,String>>();
		try
		{
			CSVReader reader = new CSVReader(new FileReader(fileName));
			file.columns = reader.readNext();
			if (file.columns != null)
			{
				int userNameColumn = 0;
				for (int i = 0; i < file.columns.length; i++)
					if ("accountName".equals(file.columns[i]))
					{
						userNameColumn = i;
					}
				for (String[] values = reader.readNext();
						values != null;
						values = reader.readNext())
				{
					Map<String,String> map = new HashMap<String, String>();
					for (int i = 0; i < values.length && i < file.columns.length; i++)
					{
						map.put(file.columns[i], values[i]);
					}
					String key = values[userNameColumn];
					file.props.put(key, map);
				}
			}
			reader.close ();
		}
		catch (FileNotFoundException e)
		{
			file.columns = new String [] {
					"accountName", "userName", "firstName", "lastName", "lastName2", "primaryGroup", "groups"
			};
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
			Map<String,String> data = props.get(user);
			for (int i = 0; i < columns.length;i++)
			{
				values[i] = data.get(columns[i]);
				if (values[i] == null)
					values[i] = "";
			}
			writer.writeNext(values);
		}
		writer.close();
	}
	
	public Map<String,String> getUserData (String user)
	{
		return props.get(user);
	}

	public void addUserData (String user, Map<String, String> data)
	{
		props.put(user, data);
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
