public object ExecuteScalar(string connectionString, CommandType commandType, string commandText, out string _errormsg, params SqlParameter[] commandParameters)
        {
            if (connectionString == null || connectionString.Length == 0) throw new ArgumentNullException("connectionString");

            using (DbConnection connection = _factory.CreateConnection())
            {
                connection.ConnectionString = "";
                connection.Open();
                return ExecuteScalar(connection, commandType, commandText, out _errormsg, commandParameters);
            }
        }

private object ExecuteScalar(DbConnection connection, CommandType commandType, string commandText, out string _errormsg, params SqlParameter[] commandParameters)
{
	if (connection == null) throw new ArgumentNullException("connection");

	// Create a command and prepare it for execution
	
		using (DbCommand cmd = connection.CreateCommand())
		{
			PrepareCommand(cmd, commandType, commandText, commandParameters);
			var dbReader = cmd.ExecuteScalar();
			_errormsg = DBException(cmd);
			return dbReader;
		}
	
			 
}

private string DBException(DbCommand dbCommandObject)
{
	string errorMessage = "";
	bool check = true;
	if (dbCommandObject.Parameters["@ErrorMessage"].Value == DBNull.Value)
	{
		check = false;
	}
	else if (dbCommandObject.Parameters["@ErrorMessage"].Value == null)
	{
		check = false;
	}
	else if (String.IsNullOrEmpty(Convert.ToString(dbCommandObject.Parameters["@ErrorMessage"].Value)))
	{
		check = false;
	}
	if (check)
	{
		errorMessage = dbCommandObject.Parameters["@ErrorMessage"].Value.ToString();
		if (dbCommandObject.Connection != null)
		{
			dbCommandObject.Connection.Close();
		}
	}
	return errorMessage;
}

private void PrepareCommand(DbCommand command, CommandType commandType, string commandText, IEnumerable<SqlParameter> paramArray)
{
	if (command == null) throw new ArgumentNullException("command");
	if (commandText == null || commandText.Length == 0) throw new ArgumentNullException("commandText");
	
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

====================================================================
public MyRtmResponse<dynamic> GetLookUp(MyRtmRequest<dynamic> req)
{
	MyRtmResponse<dynamic> resp = new MyRtmResponse<dynamic>();
	var sqlParams = new SqlParameter[1];
	sqlParams[0] = new SqlParameter() {
		ParameterName = "@JsonReq",
		SqlDbType=SqlDbType.NVarChar,
		Direction = ParameterDirection.Input,
		Value= JsonSerializer.Serialize(req)
	};
	resp.Data=_iSqlHelper.ExecuteScalar("test",CommandType.StoredProcedure, "CricInfoTest_iu", out string validationMsg, sqlParams);
	
	return resp;
}
=====================================================================
public class MyRtmRequest<T>
    {
        public T Data { get; set; }
        public string Operstion { get; set; }
        public RtmUserData UserData { get; set; }
    }

    public class MyRtmResponse<T>
    {
        public T Data { get; set; }
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public dynamic CacheData { get; set; }
    }

    public class RtmUserData
    {
        public string UserName { get; set; }
        public string RoleId { get; set; }
        public string Brand { get; set; }
        public string RequestIP { get; set; }
    }
=======================================================================
USE [CricInfo]
GO
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
ALTER PROCEDURE [dbo].[CricInfoTest_iu]
@JsonReq			NVARCHAR(max),
@ErrorMessage	VARCHAR(MAX)		OUTPUT

	

AS
SET NOCOUNT ON
--SET XACT_ABORT ON
--Declare @ErrorNo		INT;
--DECLARE @ErrorSeverity	INT;  
--DECLARE @ErrorState		INT;
BEGIN TRY
--SET @ErrorMessage = 'User Not found'
--return
--RAISERROR (@ErrorMessage, 10,1)
--PRINT 'hi'
SELECT *
FROM OPENJSON(@JsonReq)
  WITH (
    Operation NVARCHAR(50) 'strict $.Operatio',
    UserName NVARCHAR(50) '$.Data.UserName',
    uPassword NVARCHAR(50) '$.Data.Password'
  ) FOR JSON PATH ;
END TRY
BEGIN CATCH
	/*SELECT	@ErrorMessage	=	ERROR_MESSAGE(),
			@ErrorNo		=	ERROR_NUMBER(),
			@ErrorSeverity = ERROR_SEVERITY(),  
			@ErrorState = ERROR_STATE(); */
	--RAISERROR (@ErrorMessage,@ErrorSeverity,@ErrorState);
	--SET @ErrorMessage = ERROR_MESSAGE();
	--SET @ErrorSeverity = ERROR_SEVERITY();
	--SET @ErrorState = ERROR_MESSAGE();

	/*IF @ErrorSeverity != 10
	BEGIN
		SET @ErrorSeverity=11;
	END
	select @ErrorSeverity*/
	--SELECT @ErrorMessage,@ErrorSeverity,@ErrorState
	/*DECLARE @ErrorMess NVARCHAR(4000);
    DECLARE @ErrorSeverity INT;
    DECLARE @ErrorState INT;
	DECLARE @ErrorNo INT;
	SELECT 
        @ErrorMess = ERROR_MESSAGE(),
        @ErrorSeverity = ERROR_SEVERITY(),
        @ErrorState = ERROR_STATE(),
		@ErrorNo		=	ERROR_NUMBER();
		--SELECT @ErrorSeverity;*/
    RAISERROR ('error found',16, 1)
	--THROW 51000, @ErrorMess, 1
END CATCH
============================================
https://naturalselectiondba.wordpress.com/2016/03/01/throw-and-output-variables-output-variables-are-not-returned-when-an-error-occurs/
https://stackoverflow.com/questions/22126828/catch-sql-raise-error-in-c-sharp