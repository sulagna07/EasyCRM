USE [SaraSwata]
GO
/****** Object:  StoredProcedure [dbo].[UserLogin_r]    Script Date: 26-07-2019 23:04:31 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [dbo].[UserLogin_r]
	@UserName varchar(30),
	@Password varchar(30),
	@ErrorMessage	VARCHAR(MAX)		OUTPUT

AS
Begin
	BEGIN TRY
		SET @ErrorMessage=''

		IF EXISTS(SELECT 1 FROM users WHERE UserName=@UserName OR EmailId=@UserName)
		BEGIN
			IF EXISTS(SELECT 1 FROM users WHERE (UserName=@UserName OR EmailId=@UserName) AND Password=@Password)
			BEGIN
				SELECT	FirstName,LastName 
				FROM	users  
				WHERE	UserName=@UserName OR EmailId=@UserName
			END
			ELSE
			BEGIN
				SET @ErrorMessage='You have entered wrong password'
				RAISERROR(@ErrorMessage,0,0)
			END
		END
		ELSE
		BEGIN
			SET @ErrorMessage='UserName or Email does not exist'
			RAISERROR(@ErrorMessage,0,0)
		END
	END TRY
	BEGIN CATCH
		SET @ErrorMessage=ERROR_SEVERITY()+' : '+ERROR_STATE()+' : '+ERROR_PROCEDURE()+' : '+ERROR_LINE()+' : '+ERROR_MESSAGE()
		RAISERROR(@ErrorMessage,1,16)	
	END CATCH
End
