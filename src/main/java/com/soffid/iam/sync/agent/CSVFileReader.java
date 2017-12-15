package com.soffid.iam.sync.agent;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import au.com.bytecode.opencsv.CSVReader;
import es.caib.seycon.ng.exception.InternalErrorException;

public class CSVFileReader {
	private String[] columns;
	private CSVReader reader;
	public CSVFileReader(String fileName) throws IOException
	{
		reader = new CSVReader(new FileReader(fileName));
		columns = reader.readNext();
	}
	
	public Map<String,String> readLine() throws IOException
	{
		String[] values = reader.readNext();
		if (values == null)
			return null;

		Map<String,String> map = new HashMap<String, String>();
		for (int i = 0; i < values.length && i < columns.length; i++)
		{
			map.put(columns[i], values[i]);
		}
		return map;		
	}

}
