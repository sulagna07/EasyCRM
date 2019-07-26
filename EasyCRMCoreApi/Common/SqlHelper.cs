using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;

namespace Common
{
    /// <summary>
    /// The SqlHelper class is intended to encapsulate high performance, scalable best practices for
    /// common uses of SqlClient
    /// </summary>
    public sealed class SqlHelper
    {

        #region private utility methods & constructors

        private SqlHelper()
        {
            
        }

        
        private static void PrepareCommand(ref SqlCommand command, SqlConnection connection, CommandType commandType, string commandText, IEnumerable<SqlParameter> paramArray)
        {
            if (command == null) throw new ArgumentNullException("command");
            if (commandText == null || commandText.Length == 0) throw new ArgumentNullException("commandText");
            
            command.Connection = connection;
            command.CommandText = commandText;
            command.CommandType = commandType;
            
            if (paramArray != null)
            {
                foreach (SqlParameter currentParam in paramArray)
                {
                    command.Parameters.Add(currentParam);
                }
            }

            command.Parameters.Add(new SqlParameter("@ErrorMessage", SqlDbType.VarChar, 255, Convert.ToString(string.Empty)));
            command.Parameters["@ErrorMessage"].Direction = ParameterDirection.Output;
            command.Parameters["@ErrorMessage"].Size = 8000;
            return;
        }

        #endregion private utility methods & constructors

        #region ExecuteDataset

        public static DataSet ExecuteDataset(string connectionString, CommandType commandType, string commandText, out string _errormsg, params SqlParameter[] commandParameters)
        {
            if (connectionString == null || connectionString.Length == 0) throw new ArgumentNullException("connectionString");

            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                connection.Open();
                return ExecuteDataset(connection, commandType, commandText,out _errormsg, commandParameters);
            }
        }

        
        public static DataSet ExecuteDataset(SqlConnection connection, CommandType commandType, string commandText, out string _errormsg, params SqlParameter[] commandParameters)
        {
            if (connection == null) throw new ArgumentNullException("connection");

            SqlCommand cmd = new SqlCommand();
            PrepareCommand(ref cmd, connection, commandType, commandText, commandParameters);

            using (SqlDataAdapter da = new SqlDataAdapter(cmd))
            {
                DataSet ds = new DataSet();
                da.Fill(ds);
                _errormsg = cmd.Parameters["@ErrorMessage"].Value.ToString();
                cmd.Parameters.Clear();
                connection.Close();
                return ds;
            }
        }
        
        #endregion ExecuteDataset
    }
}
