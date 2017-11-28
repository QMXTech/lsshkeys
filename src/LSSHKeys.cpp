////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// LSSHKeys.cpp
// Matthew J. Schultz | Created : 16OCT17 | Last Modified : 31OCT17 by Matthew J. Schultz
// Version : 0.0.1
// This is the main source file for 'LSSHKeys', a program to fetch SSH Public Keys from an LDAP directory.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2017 QuantuMatriX Software, a QuantuMatriX Technologies Cooperative Partnership.
//
// This file is part of 'LSSHKeys'.
//
// 'LSSHKeys' is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any later version.
//
// 'LSSHKeys' is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along with 'LSSHKeys'.  If not, see <http://www.gnu.org/licenses/>.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Header Files
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "../include/LSSHKeys.hpp"

using namespace std;
using namespace Utility;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The 'main' Function
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int main( int ArgumentCount, char* ArgumentValues[] )
{
	// Create local variables.

		bool ArgumentC = false;
		bool ArgumentD = false;
		bool ErrorOccurred = false;
		int ArgumentIndex;
		int AttributeCount;
		int AttributeListLength;
		int CfgValuesPreProcessed = 0;
		int ErrorCode;
		int IntegerValue;
		int Scope;
		int ValueIndex;
		size_t FindPosition;
		string Argument;
		string ArgumentLower;
		string AttributeName;
		string CfgFileName;
		string ErrorMessage;
		string ExecutedCommand;
		string Filter;
		string LogLevelName;
		string LogMethodName;
		string StringValue;
		string Username;
		struct timeval Seconds;
		ifstream CfgFile;
		ofstream LogFile;
		queue< string > ArgumentQueue;
		Config Cfg;
		Output::Method LogMethod;
		Output::Level LogLevel;
		Output Log;
		char* Attribute = nullptr;
		char** AttributeList = { nullptr };
		char* ErrorMessageBuffer = nullptr;
		char* LogFileName = nullptr;
		BerElement* AttributeIterator = nullptr;
		BerValue* Credentials = nullptr;
		BerValue* ServerCredentials = nullptr;
		BerValue** Values = nullptr;
		LDAP* LDAPInterface = nullptr;
		LDAPMessage* Entry = nullptr;
		LDAPMessage* Response = nullptr;

	// Create a lambda to free memory.

		auto FreeMemory = [ & ]()
		{
			if( ErrorMessageBuffer != nullptr )
			{
				LDAPMemFree( ErrorMessageBuffer );
			}

			if( Attribute != nullptr )
			{
				LDAPMemFree( Attribute );
			}

			if( AttributeList != nullptr )
			{
				CStringArrayFree( AttributeList, AttributeListLength );
			}

			if( LogFileName != nullptr )
			{
				CStringFree( LogFileName );
			}

			if( AttributeIterator != nullptr )
			{
				BerFree( AttributeIterator );
			}

			if( Credentials != nullptr )
			{
				BerValueFree( Credentials );
			}

			if( Values != nullptr )
			{
				LDAPValueFreeLen( Values );
			}

			if( Response != nullptr )
			{
				LDAPMsgFree( Response );
			}

			// Entry exists within Response apparently...
			/*if( Entry != nullptr )
			{
				LDAPMsgFree( Entry );
			}*/

			if( LDAPInterface != nullptr )
			{
				LDAPClose( LDAPInterface );
			}

		};

	// Handle all exceptions not otherwise caught before Output is initialized.

		try
		{
			// Copy arguments to queue.

				for( ArgumentIndex = 0; ArgumentIndex < ArgumentCount; ArgumentIndex++ )
					ArgumentQueue.push( ArgumentValues[ ArgumentIndex ] );

			// Check if we have any arguments that need attention or validate username; log error to syslog and exit on failure.

				ExecutedCommand = ArgumentQueue.front();
				ArgumentQueue.pop();

				for( ; !ArgumentQueue.empty(); ArgumentQueue.pop() )
				{
					Argument = ArgumentQueue.front();
					ArgumentLower = Argument;

					transform( ArgumentLower.begin(), ArgumentLower.end(), ArgumentLower.begin(), ::tolower );

					if( ( ArgumentLower == "--help" ) ||
					    ( ArgumentLower == "-h" ) ||
					    ( ArgumentLower == "-?" ) ||
					    ( ArgumentLower == "--version" ) ||
					    ( ArgumentLower == "-v" ) )
					{
						cout << NAME << " version: " << LSSHKEYS_VER_MAJOR << '.' << LSSHKEYS_VER_MINOR << '.' << LSSHKEYS_VER_PATCH
						             << endl;
						cout << endl;
						cout << "Usage: " << BINARY << " [OPTION]... username" << endl;
						cout << endl;
						cout << "  -d, --dbg, --debug		Enable debug mode." << endl;
						cout << "  -c, --conf, --config		Set user defined configuration file." << endl;
						cout << endl;
						cout << "Configuration options may be set in the file: " << CONFIG << "." << endl;
						cout << "For details about configuration options, please see " << CONFIG_FILE << "(5)." << endl << endl;
						cout << "For more details please see " << BINARY << "(8)" << " or <" PROJECT_URL << ">." << endl;
						cout << "Report bugs at <" << BUG_URL << ">." << endl;
						return 0;
					}

					if( ( ArgumentLower.find("--config") == 0 ) || 
					    ( ArgumentLower.find("--conf") == 0 ) || 
					    ( ArgumentLower.find("-c") == 0 ) )
					{
						FindPosition = Argument.find('=');

						if( FindPosition != string::npos )
						{
							if( ACCESS_F( Argument.substr( FindPosition + 1, Argument.length() ).c_str() ) )
							{
								if( ACCESS_R( Argument.substr( FindPosition + 1, Argument.length() ).c_str() ) )
								{
									CfgFileName = Argument.substr( FindPosition + 1, Argument.length() );
								}
								else
								{
									PreLogCritical( "Cannot open configuration file : " + ErrnoToString() );
								}
							}
							else
							{
								PreLogCritical( "Cannot open configuration file : " + ErrnoToString() );
							}
						}
						else
						{
							FindPosition = Argument.find('/');

							if( FindPosition != string::npos )
							{
								if ( Argument[ FindPosition - 1 ] == '.' )
								{
									FindPosition--;
								}

								if( ACCESS_F( Argument.substr( FindPosition, Argument.length() ).c_str() ) )
								{
									if( ACCESS_R( Argument.substr( FindPosition, Argument.length() ).c_str() ) )
									{
										CfgFileName = Argument.substr( FindPosition, Argument.length() );
									}
									else
									{
										PreLogCritical( "Cannot open configuration file : " + ErrnoToString() );
									}
								}
								else
								{
									PreLogCritical( "Cannot open configuration file : " + ErrnoToString() );
								}
							}
							else
							{
								if( ( Argument.substr( 0, 2 ) == "-c" ) && ( Argument[ 2 ] ) )
								{
									if( ACCESS_F( Argument.substr( 2, Argument.length() ).c_str() ) )
									{
										if( ACCESS_R( Argument.substr( 2, Argument.length() ).c_str() ) )
										{
											CfgFileName = Argument.substr( 2, Argument.length() );
										}
										else
										{
											PreLogCritical( "Cannot open configuration file : "
											                + ErrnoToString() );
										}
									}
									else
									{
										PreLogCritical( "Cannot open configuration file : " + ErrnoToString() );
									}
								}
								else if( ( Argument.substr( 0, 6 ) == "--conf" ) && ( Argument[ 6 ] ) )
								{
									if( ACCESS_F( Argument.substr( 6, Argument.length() ).c_str() ) )
									{
										if( ACCESS_R( Argument.substr( 6, Argument.length() ).c_str() ) )
										{
											CfgFileName = Argument.substr( 6, Argument.length() );
										}
										else
										{
											PreLogCritical( "Cannot open configuration file : "
											                + ErrnoToString() );
										}
									}
									else
									{
										PreLogCritical( "Cannot open configuration file : " + ErrnoToString() );
									}
								}
								else if( ( Argument.substr( 0, 8 ) == "--config" ) && ( Argument[ 8 ] ) )
								{
									if( ACCESS_F( Argument.substr( 8, Argument.length() ).c_str() ) )
									{
										if( ACCESS_R( Argument.substr( 8, Argument.length() ).c_str() ) )
										{
											CfgFileName = Argument.substr( 8, Argument.length() );
										}
										else
										{
											PreLogCritical( "Cannot open configuration file : "
											                + ErrnoToString() );
										}
									}
									else
									{
										PreLogCritical( "Cannot open configuration file : " + ErrnoToString() );
									}
								}
								else
								{
									ArgumentQueue.pop();
									Argument = ArgumentQueue.front();
		
									if( ACCESS_F( Argument.c_str() ) )
									{
										if( ACCESS_R( Argument.c_str() ) )
										{
											CfgFileName = Argument;
										}
										else
										{
											PreLogCritical( "Cannot open configuration file : "
											                + ErrnoToString() );
										}
									}
									else
									{
										PreLogCritical( "Cannot open configuration file : " + ErrnoToString() );
									}
								}
							}
						}

						CfgFile.open( CfgFileName );
						Cfg.Init( CfgFile );
						ArgumentC = true;
						
						continue;
					}

					if( ( ArgumentLower == "--debug" ) || ( ArgumentLower == "--dbg" ) || ( ArgumentLower == "-d" ) )
					{
						LogMethod = Output::Method::Stdio;
						LogLevel = DEBUG;
						LogMethodName = "stdio";
						LogLevelName = "debug";
						ArgumentD = true;

						cerr << "[ Information ] : Starting in debug mode." << endl;

						continue;
					}

					if( ArgumentQueue.size() == 1 )
					{
						if( regex_match( Argument, regex( "^[a-z][-a-z0-9]*" ) ) )
						{
							Username = Argument;
						}
						else
						{
							PreLogCritical( ErrnoToString( EINVAL ) );
						}
					}
					else
					{
						PreLogCritical( ErrnoToString( EINVAL ) );
					}
				}

				if( !ArgumentC )
				{
					CfgFileName = CONFIG_FILE;
					Cfg.Init();
				}

			// Get the log level configuration parameter first or use the default setting.
			
				if( Cfg.Exists( "loglevel" ) && ( !ArgumentD ) )
				{
					StringValue = Cfg.GetValue( "loglevel" );
					transform( StringValue.begin(), StringValue.end(), StringValue.begin(), ::tolower );

					if( ( StringValue == "debug" ) || ( StringValue == "7" ) )
					{
						LogLevelName = "debug";
						LogLevel = DEBUG;
					}
					else if( ( StringValue == "information" ) || ( StringValue == "info" ) || ( StringValue == "6" ) )
					{
						LogLevelName = "information";
						LogLevel = INFORMATION;
					}
					else if( ( StringValue == "notice" ) || ( StringValue == "5" ) )
					{
						LogLevelName = "notice";
						LogLevel = NOTICE;
					}
					else if( ( StringValue == "warning" ) || ( StringValue == "warn" ) || ( StringValue == "4" ) )
					{
						LogLevelName = "warning";
						LogLevel = WARNING;
					}
					else if( ( StringValue == "error" ) || ( StringValue == "err" ) || ( StringValue == "3" ) )
					{
						LogLevelName = "error";
						LogLevel = ERROR;
					}
					else if( ( StringValue == "critical" ) || ( StringValue == "crit" ) || ( StringValue == "2" ) )
					{
						LogLevelName = "critical";
						LogLevel = CRITICAL;
					}
					else if( ( StringValue == "alert" ) || ( StringValue == "1" ) )
					{
						LogLevelName = "alert";
						LogLevel = ALERT;
					}
					else if( ( StringValue == "emergency" ) || ( StringValue == "emerg" ) || ( StringValue == "0" ) )
					{
						LogLevelName = "emergency";
						LogLevel = EMERGENCY;
					}
					else
					{
						PreLogCritical( "Value of 'loglevel' parameter invalid." );
					}

					CfgValuesPreProcessed++;
				}
				else
				{
					if( !ArgumentD )
						LogLevel = ( Output::Level ) DEFAULT_LOG_LEVEL;
				}

			// Get the log type configuration parameter if it exists or default to syslog. Ensure file is writeable or createable
			// when logging to file. Also initialize log. Send error to available log methods and exit on critical error.

				if( Cfg.Exists( "log" ) && ( !ArgumentD ) )
				{
					StringValue = Cfg.GetValue( "log" );
					transform( StringValue.begin(), StringValue.end(), StringValue.begin(), ::tolower );

					if( StringValue == "syslog" )
					{
						LogMethodName = "syslog";
						LogMethod = Output::Method::Syslog;
					}
					else if( ( StringValue == "stdio" ) || ( StringValue == "stdout" ) || ( StringValue == "stderr" ) )
					{
						LogMethodName = "stdio";
						LogMethod = Output::Method::Stdio;
					}
					else
					{
						if( ACCESS_F( Cfg.GetValue( "log" ).c_str() ) )
						{
							if( ACCESS_W( Cfg.GetValue( "log" ).c_str() ) )
							{
								LogMethodName = "file: " + Cfg.GetValue( "log" );
								LogMethod = Output::Method::File;
								LogFile.open( Cfg.GetValue( "log" ).c_str(), ( fstream::out | fstream::app ) );
							}
							else
							{
								PreLogCritical( "Cannot open log file for writing : " + ErrnoToString() );
							}
						}
						else
						{
							if( errno == ENOENT )
							{
								LogFileName = new char[ Cfg.GetValue( "log" ).length() + 1 ];
								strcpy( LogFileName, Cfg.GetValue( "log" ).c_str() );

								if( ACCESS_F( dirname( LogFileName ) ) )
								{
									if( ACCESS_W( dirname( LogFileName ) ) )
									{
										CStringFree( LogFileName );

										LogMethodName = "file: " + Cfg.GetValue( "log" );
										LogMethod = Output::Method::File;
										LogFile.open( Cfg.GetValue( "log" ).c_str(), fstream::out );
									}
									else
									{
										FreeMemory();
										PreLogCritical( "Cannot open log file for writing : " + ErrnoToString() );
									}
								}
								else
								{
									FreeMemory();
									PreLogCritical( "Cannot open log file for writing : " + ErrnoToString() );
								}
							}
							else
							{
								PreLogCritical( "Cannot open log file for writing : " + ErrnoToString() );
							}
						}
					}

					CfgValuesPreProcessed++;
				}
				else
				{
					if( !ArgumentD )
					{
						LogMethodName = "syslog";
						LogMethod = Output::Method::Syslog;
					}
				}

				if( LogMethod == Output::Method::File )
					Log.Init( LogFile, LogLevel );
				else
					Log.Init( LogMethod, LogLevel );

				Log << INFORMATION << "Processing configuration file: '" << CfgFileName << "'" << endl;

				Log << INFORMATION << "Log successfully started using: '" << LogMethodName << "' at log level: '" << LogLevelName << "'"
				                   << endl;
		}
		catch( out_of_range& Exception )
		{
			FreeMemory();
			PreLogCritical( string( Exception.what() ) + " : " + ErrnoToString( ERANGE ) );
		}
		catch( length_error& Exception )
		{
			FreeMemory();
			PreLogCritical( string( Exception.what() ) + " : " + ErrnoToString( EOVERFLOW ) );
		}
		catch( ios_base::failure& Exception )
		{
			FreeMemory();
			PreLogCritical( string( Exception.what() ) + " : " + ErrnoToString( EIO ) );
		}
		catch( bad_alloc& Exception )
		{
			FreeMemory();
			PreLogCritical( string( Exception.what() ) + " : " + ErrnoToString( ENOMEM ) );
		}
		catch( invalid_argument& Exception )
		{
			FreeMemory();
			PreLogCritical( string( Exception.what() ) + " : " + ErrnoToString( EINVAL ) );
		}
		catch( exception& Exception )
		{
			FreeMemory();
			PreLogCritical( string( Exception.what() ) + " : " + ErrnoToString( EBADMSG ) );
		}

	// Handle all exceptions not otherwise caught after Output is initialized and determined to be good.

		try
		{
			// Log configuration values if loglevel is debug.

				if( LogLevel == DEBUG )
				{
					Log << DEBUG << "Configuration values: " << endl;
					Log << DEBUG << '{' << endl;
					for( const pair< string, string > &CfgPair : Cfg.GetConfigurationMap() )
					{
						Log << DEBUG << "    '" << CfgPair.first << "' = '" << CfgPair.second << "'" << endl;
					}
					Log << DEBUG << '}' << endl;
				}

			// Ensure we have enough configuration parameters and/or the file exists.

				if( ( Cfg.Size() - CfgValuesPreProcessed ) < 2 )
				{
					Log << CRITICAL << "Not enough configuration parameters found. Aborting." << endl;
				}


			// Initialize LDAP using 'uri' configuration parameter.

				Log << DEBUG << "Checking if 'uri' parameter exists... ";

				if( Cfg.Exists( "uri" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'uri' is: '" << Cfg.GetValue( "uri" ) << "'" << endl;

					if( ( ErrorCode = ldap_initialize( &LDAPInterface, Cfg.GetValue( "uri" ).c_str() ) ) != LDAP_SUCCESS )
					{
						FreeMemory();
						Log << CRITICAL << "ldap_initialize(): " << ldap_err2string( ErrorCode ) << ". Cannot continue." << endl;
					}
					else
					{
						Log << INFORMATION << "LDAP interface initialized successfully." << endl;
					}
				}
				else
				{
					Log << "No." << endl;
					Log << CRITICAL << "Value of 'uri' parameter undefined." << endl;
				}

			// Set LDAP_OPT_PROTOCOL_VERSION using 'ldap_version' configuration parameter.

				Log << DEBUG << "Checking if 'ldap_version' parameter exists... ";

				if( Cfg.Exists( "ldap_version" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'ldap_version' is: '" << Cfg.GetValue( "ldap_version" ) << "'" << endl;

					try
					{
						IntegerValue = stoi( Cfg.GetValue( "ldap_version" ) );
					}
					catch( invalid_argument& Exception )
					{
						Log << WARNING << "Value of 'ldap_version' parameter cannot be parsed. '" << Exception.what() << "' : "
						               << ErrnoToString( EINVAL ) << ". Defaulting to LDAPv3." << endl;

						IntegerValue = LDAP_VERSION3;
					}
					catch( out_of_range& Exception )
					{
						Log << WARNING << "Value of 'ldap_version' parameter cannot be parsed. '" << Exception.what() << "' : "
						               << ErrnoToString( ERANGE ) << ". Defaulting to LDAPv3." << endl;

						IntegerValue = LDAP_VERSION3;
					}
					catch( exception& Exception )
					{
						Log << WARNING << "Value of 'ldap_version' parameter cannot be parsed. '" << Exception.what() << "' threw an "
						                  "unhandled exception. Defaulting to LDAPv3." << endl;

						IntegerValue = LDAP_VERSION3;
					}

					if( IntegerValue == 2 )
					{
						Log << NOTICE << "You are using LDAPv2. Please ensure you intend to use this version and/or consider upgrading"
						                 " to LDAPv3." << endl;
						
						IntegerValue = LDAP_VERSION2;
					}
					else if( ( IntegerValue > 3 ) || ( IntegerValue < 2 ) )
					{
						Log << WARNING << "Value of 'ldap_version' parameter invalid. Defaulting to LDAPv3." << endl;

						IntegerValue = LDAP_VERSION3;
					}

					if( ( ErrorCode = ldap_set_option( LDAPInterface, LDAP_OPT_PROTOCOL_VERSION, &IntegerValue ) ) != LDAP_SUCCESS )
					{
						FreeMemory();
						Log << CRITICAL << "ldap_set_option( LDAP_VERSION ): " << ldap_err2string( ErrorCode ) << ". Cannot continue."
						                << endl;
					}
					else
					{
						Log << INFORMATION << "ldap_set_option( LDAP_VERSION ): Success." << endl;
					}
				} 
				else 
				{
					Log << "No. Defaulting to LDAPv3." << endl;

					IntegerValue = LDAP_VERSION3;

					if( ( ErrorCode = ldap_set_option( LDAPInterface, LDAP_OPT_PROTOCOL_VERSION, &IntegerValue ) ) != LDAP_SUCCESS ) 
					{
						FreeMemory();
						Log << CRITICAL << "ldap_set_option( LDAP_VERSION ): " << ldap_err2string( ErrorCode ) << ". Cannot continue."
						                << endl;
					}
					else
					{
						Log << INFORMATION << "ldap_set_option( LDAP_VERSION ): Success." << endl;
					}
				}

			// OpenLDAP specific configuration parameters. If these are set on any other system, they are ignored.

#				ifdef LDAP_API_FEATURE_X_OPENLDAP

				Log << DEBUG << "OpenLDAP detected." << endl;

			// Set LDAP_OPT_X_KEEPALIVE_INTERVAL using 'tcp_keepalive_interval' configuration parameter.

				Log << DEBUG << "Checking if 'tcp_keepalive_interval' parameter exists... ";

				if( Cfg.Exists( "tcp_keepalive_interval" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'tcp_keepalive_interval' is: '" << Cfg.GetValue( "tcp_keepalive_interval" ) << "'"
					             << endl;

					try
					{
						IntegerValue = stoi( Cfg.GetValue( "tcp_keepalive_interval" ) );
					}
					catch( invalid_argument& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'tcp_keepalive_interval' parameter cannot be parsed. '" << Exception.what() << "' : "
						               << ErrnoToString( EINVAL ) << ". Attempting to continue." << endl;
					}
					catch( out_of_range& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'tcp_keepalive_interval' parameter cannot be parsed. '" << Exception.what() << "' : "
						               << ErrnoToString( ERANGE ) << ". Attempting to continue." << endl;
					}
					catch( exception& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'tcp_keepalive_interval' parameter cannot be parsed. '" << Exception.what() << "' "
						                  "threw an unhandled exception. Attempting to continue." << endl;
					}

					if( !ErrorOccurred )
					{
						if( ( ErrorCode = ldap_set_option( LDAPInterface,
						                                   LDAP_OPT_X_KEEPALIVE_INTERVAL,
						                                   &IntegerValue ) ) != LDAP_SUCCESS )
						{
							Log << WARNING << "ldap_set_option( TCP_KEEPALIVE_INTERVAL ): " << ldap_err2string( ErrorCode ) << ". "
							                  "Attempting to continue." << endl;
						}
						else
						{
							Log << INFORMATION << "ldap_set_option( TCP_KEEPALIVE_INTERVAL ): Success." << endl;
						}
					}
					else
					{
						ErrorOccurred = false;
					}
				}
				else
				{
					Log << "No." << endl;
				}

			// Set LDAP_OPT_X_KEEPALIVE_IDLE using 'tcp_keepalive_idle' configuration parameter.

				Log << DEBUG << "Checking if 'tcp_keepalive_idle' parameter exists... ";

				if( Cfg.Exists( "tcp_keepalive_idle" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'tcp_keepalive_idle' is: '" << Cfg.GetValue( "tcp_keepalive_idle" ) << "'" << endl;

					try
					{
						IntegerValue = stoi( Cfg.GetValue( "tcp_keepalive_idle" ));
					}
					catch( invalid_argument& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'tcp_keepalive_idle' parameter cannot be parsed. '" << Exception.what() << "' : "
						               << ErrnoToString( EINVAL ) << ". Attempting to continue." << endl;
					}
					catch( out_of_range& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'tcp_keepalive_idle' parameter cannot be parsed. '" << Exception.what() << "' : "
						               << ErrnoToString( ERANGE ) << ". Attempting to continue." << endl;
					}
					catch( exception& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'tcp_keepalive_idle' parameter cannot be parsed. '" << Exception.what() << "' "
						                  "threw an unhandled exception. Attempting to continue." << endl;
					}

					if( !ErrorOccurred )
					{
						if( ( ErrorCode = ldap_set_option( LDAPInterface,
						                                   LDAP_OPT_X_KEEPALIVE_IDLE,
						                                   &IntegerValue ) ) != LDAP_SUCCESS ) 
						{
							Log << WARNING << "ldap_set_option( TCP_KEEPALIVE_IDLE ): " << ldap_err2string( ErrorCode ) << ". "
							                  "Attempting to continue." << endl;
						}
						else
						{
							Log << INFORMATION << "ldap_set_option( TCP_KEEPALIVE_IDLE ): Success." << endl;
						}
					}
					else
					{
						ErrorOccurred = false;
					}
				}
				else
				{
					Log << "No." << endl;
				}

			// Set LDAP_OPT_X_KEEPALIVE_PROBES using 'tcp_keepalive_probes' configuration parameter.

				Log << DEBUG << "Checking if 'tcp_keepalive_probes' parameter exists... ";

				if( Cfg.Exists( "tcp_keepalive_probes" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'tcp_keepalive_probes' is: '" << Cfg.GetValue( "tcp_keepalive_probes" ) << "'" << endl;

					try
					{
						IntegerValue = stoi( Cfg.GetValue( "tcp_keepalive_probes" ) );
					}
					catch( invalid_argument& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'tcp_keepalive_probes' parameter cannot be parsed. '" << Exception.what() << "' : "
						               << ErrnoToString( EINVAL ) << ". Attempting to continue." << endl;
					}
					catch( out_of_range& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'tcp_keepalive_probes' parameter cannot be parsed. '" << Exception.what() << "' : "
						               << ErrnoToString( ERANGE ) << ". Attempting to continue." << endl;
					}
					catch( exception& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'tcp_keepalive_probes' parameter cannot be parsed. '" << Exception.what() << "' "
						                  "threw an unhandled exception. Attempting to continue." << endl;
					}

					if( !ErrorOccurred )
					{
						if( ( ErrorCode = ldap_set_option( LDAPInterface,
						                                   LDAP_OPT_X_KEEPALIVE_PROBES,
						                                   &IntegerValue ) ) != LDAP_SUCCESS )
						{
							Log << WARNING << "ldap_set_option( TCP_KEEPALIVE_PROBES ): " << ldap_err2string( ErrorCode ) << ". "
							                  "Attempting to continue." << endl;
						}
						else
						{
							Log << INFORMATION << "ldap_set_option( TCP_KEEPALIVE_PROBES ): Success." << endl;
						}
					}
					else
					{
						ErrorOccurred = false;
					}
				}
				else
				{
					Log << "No." << endl;
				}

			// Set LDAP_OPT_TIMEOUT using 'bind_timelimit' configuration parameter.

				Log << DEBUG << "Checking if 'bind_timelimit' parameter exists... ";
				
				if( Cfg.Exists( "bind_timelimit" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'bind_timelimit' is: '" << Cfg.GetValue( "bind_timelimit" ) << "'" << endl;

					try
					{
						Seconds.tv_sec = stoi( Cfg.GetValue( "bind_timelimit" ) );
					}
					catch( invalid_argument& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'bind_timelimit' parameter cannot be parsed. '" << Exception.what() << "' : "
						               << ErrnoToString( EINVAL ) << ". Attempting to continue." << endl;
					}
					catch( out_of_range& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'bind_timelimit' parameter cannot be parsed. '" << Exception.what() << "' : "
						               << ErrnoToString( ERANGE ) << ". Attempting to continue." << endl;
					}
					catch( exception& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'bind_timelimit' parameter cannot be parsed. '" << Exception.what() << "' threw "
						                  "an unhandled exception. Attempting to continue." << endl;
					}

					if( !ErrorOccurred )
					{
						if( ( ErrorCode = ldap_set_option( LDAPInterface, LDAP_OPT_TIMEOUT, &Seconds ) ) != LDAP_SUCCESS )
						{
							Log << WARNING << "ldap_set_option( BIND_TIMELIMIT ): " << ldap_err2string( ErrorCode ) << ". "
							                  "Attempting to continue." << endl;
						}
						else
						{
							Log << INFORMATION << "ldap_set_option( BIND_TIMELIMIT ): Success." << endl;
						}
					}
					else
					{
						ErrorOccurred = false;
					}
				}
				else
				{
					Log << "No." << endl;
				}

			// Set LDAP_OPT_NETWORK_TIMEOUT using 'idle_timelimit' configuration parameter.

				Log << DEBUG << "Checking if 'idle_timelimit' parameter exists... ";
				
				if( Cfg.Exists( "idle_timelimit" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'idle_timelimit' is: '" << Cfg.GetValue( "idle_timelimit" ) << "'" << endl;

					try
					{
						Seconds.tv_sec = stoi( Cfg.GetValue( "idle_timelimit" ) );
					}
					catch( invalid_argument& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'idle_timelimit' parameter cannot be parsed. '" << Exception.what() << "' : "
						               << ErrnoToString( EINVAL ) << ". Attempting to continue." << endl;
					}
					catch( out_of_range& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'idle_timelimit' parameter cannot be parsed. '" << Exception.what() << "' : "
						               << ErrnoToString( ERANGE ) << ". Attempting to continue." << endl;
					}
					catch( exception& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'idle_timelimit' parameter cannot be parsed. '" << Exception.what() << "' threw "
						                  "an unhandled exception. Attempting to continue." << endl;
					}

					if( !ErrorOccurred )
					{
						if( ( ErrorCode = ldap_set_option( LDAPInterface, LDAP_OPT_NETWORK_TIMEOUT, &Seconds ) ) != LDAP_SUCCESS )
						{
							Log << WARNING << "ldap_set_option( IDLE_TIMELIMIT ): " << ldap_err2string( ErrorCode ) << ". "
							                  "Attempting to continue." << endl;
						}
						else
						{
							Log << INFORMATION << "ldap_set_option( IDLE_TIMELIMIT ): Success." << endl;
						}
					}
					else
					{
						ErrorOccurred = false;
					}
				}
				else
				{
					Log << "No." << endl;
				}

			// End of OpenLDAP specific configuration parameters.

#				endif

			// Set LDAP_OPT_TIMELIMIT using 'timelimit' configuration parameter.

				Log << DEBUG << "Checking if 'timelimit' parameter exists... ";
				
				if( Cfg.Exists( "timelimit" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'timelimit' is: '" << Cfg.GetValue( "timelimit" ) << "'" << endl;

					try
					{
						IntegerValue = stoi( Cfg.GetValue( "timelimit" ) );
					}
					catch( invalid_argument& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'timelimit' parameter cannot be parsed. '" << Exception.what() << "' : "
						               << ErrnoToString( EINVAL ) << ". Attempting to continue." << endl;
					}
					catch( out_of_range& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'timelimit' parameter cannot be parsed. '" << Exception.what() << "' : "
								<< ErrnoToString( ERANGE ) << ". Attempting to continue." << endl;
					}
					catch( exception& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'timelimit' parameter cannot be parsed. '" << Exception.what() << "' threw "
									"an unhandled exception. Attempting to continue." << endl;
					}

					if( !ErrorOccurred )
					{
						if( ( ErrorCode = ldap_set_option( LDAPInterface, LDAP_OPT_TIMELIMIT, &IntegerValue ) ) != LDAP_SUCCESS )
						{
							Log << WARNING << "ldap_set_option( TIMELIMIT ): " << ldap_err2string( ErrorCode ) << ". "
										"Attempting to continue." << endl;
						}
						else
						{
							Log << INFORMATION << "ldap_set_option( TIMELIMIT ): Success." << endl;
						}
					}
					else
					{
						ErrorOccurred = false;
					}
				}
				else
				{
					Log << "No." << endl;
				}

			// Set LDAP_OPT_X_TLS_CACERTDIR using 'tls_cacertdir' configuration parameter.

				Log << DEBUG << "Checking if 'tls_cacertdir' parameter exists... ";

				if( Cfg.Exists( "tls_cacertdir" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'tls_cacertdir' is: '" << Cfg.GetValue( "tls_cacertdir" ) << "'" << endl;
					Log << DEBUG << "Checking if '" << Cfg.GetValue( "tls_cacertdir" ) << "' exists...";

					if( ACCESS_F( Cfg.GetValue( "tls_cacertfile" ).c_str() ) )
					{
						Log << "Yes." << endl;
						Log << DEBUG << "Checking if '" << Cfg.GetValue( "tls_cacertdir" ) << "' is searchable...";

						if( ACCESS_X( Cfg.GetValue( "tls_cacertfile" ).c_str() ) )
						{
							Log << "Yes." << endl;

							if( ( ErrorCode = ldap_set_option( LDAPInterface,
							                                   LDAP_OPT_X_TLS_CACERTDIR,
							                                   Cfg.GetValue( "tls_cacertdir" ).c_str() ) ) != LDAP_SUCCESS )
							{
								Log << WARNING << "ldap_set_option( TLS_CACERTDIR ): " << ldap_err2string( ErrorCode ) << ". "
								                  "Attempting to continue." << endl;
							}
							else
							{
								Log << INFORMATION << "ldap_set_option( TLS_CACERTDIR ): Success." << endl;
							}
						}
						else
						{
							Log << "No." << endl;
							Log << WARNING << "ldap_set_option( TLS_CACERTDIR ): " << ErrnoToString() << ". Attempting to "
							                  "continue." << endl;
						}
					}
					else
					{
						Log << "No." << endl;
						Log << WARNING << "ldap_set_option( TLS_CACERTDIR ): " << ErrnoToString() << ". Attempting to continue."
						               << endl;
					}
				}
				else
				{
					Log << "No." << endl;
				}

			// Set LDAP_OPT_X_TLS_CACERTFILE using 'tls_cacertfile' configuration parameter.

				Log << DEBUG << "Checking if 'tls_cacertfile' parameter exists... ";

				if( Cfg.Exists( "tls_cacertfile" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'tls_cacertfile' is: '" << Cfg.GetValue( "tls_cacertfile" ) << "'" << endl;
					Log << DEBUG << "Checking if '" << Cfg.GetValue( "tls_cacertfile" ) << "' exists...";

					if( ACCESS_F( Cfg.GetValue( "tls_cacertfile" ).c_str() ) )
					{
						Log << "Yes." << endl;
						Log << DEBUG << "Checking if '" << Cfg.GetValue( "tls_cacertfile" ) << "' is readable...";

						if( ACCESS_R( Cfg.GetValue( "tls_cacertfile" ).c_str() ) )
						{
							Log << "Yes." << endl;

							if( ( ErrorCode = ldap_set_option( LDAPInterface,
							                                   LDAP_OPT_X_TLS_CACERTFILE,
							                                   Cfg.GetValue( "tls_cacertfile" ).c_str() ) ) != LDAP_SUCCESS )
							{
								Log << WARNING << "ldap_set_option( TLS_CACERTFILE ): " << ldap_err2string( ErrorCode ) << ". "
								                  "Attempting to continue." << endl;
							}
							else
							{
								Log << INFORMATION << "ldap_set_option( TLS_CACERTFILE ): Success." << endl;
							}
						}
						else
						{
							Log << "No." << endl;
							Log << WARNING << "ldap_set_option( TLS_CACERTFILE ): " << ErrnoToString() << ". Attempting to "
							                  "continue." << endl;
						}
					}
					else
					{
						Log << "No." << endl;
						Log << WARNING << "ldap_set_option( TLS_CACERTFILE ): " << ErrnoToString() << ". Attempting to continue."
						               << endl;
					}
				}
				else
				{
					Log << "No." << endl;
				}

			// Set LDAP_OPT_X_TLS_CERTFILE using 'tls_cert' configuration parameter.

				Log << DEBUG << "Checking if 'tls_cert' parameter exists... ";

				if( Cfg.Exists( "tls_cert" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'tls_cert' is: '" << Cfg.GetValue( "tls_cert" ) << "'" << endl;
					Log << DEBUG << "Checking if '" << Cfg.GetValue( "tls_cert" ) << "' exists... "; 

					if( ACCESS_F( Cfg.GetValue( "tls_cert" ).c_str() ) )
					{
						Log << "Yes." << endl;
						Log << DEBUG << "Checking if '" << Cfg.GetValue( "tls_cert" ) << "' is readable...";

						if( ACCESS_R( Cfg.GetValue( "tls_cert" ).c_str() ) )
						{
							Log << "Yes." << endl;

							if( ( ErrorCode = ldap_set_option( LDAPInterface,
							                                   LDAP_OPT_X_TLS_CERTFILE,
							                                   Cfg.GetValue( "tls_cert" ).c_str() ) ) != LDAP_SUCCESS )
							{
								Log << WARNING << "ldap_set_option( TLS_CERT ): " << ldap_err2string( ErrorCode ) << ". "
								                  "Attempting to continue." << endl;
							}
							else
							{
								Log << INFORMATION << "ldap_set_option( TLS_CERT ): Success." << endl;
							}
						}
						else
						{
							Log << "No." << endl;
							Log << WARNING << "ldap_set_option( TLS_CERT ): " << ErrnoToString() << ". Attempting to continue."
							               << endl;
						}
					}
					else
					{
						Log << "No." << endl;
						Log << WARNING << "ldap_set_option( TLS_CERT ): " << ErrnoToString() << ". Attempting to continue." << endl;
					}
				}
				else
				{
					Log << "No." << endl;
				}

			// Set LDAP_OPT_X_TLS_KEYFILE using 'tls_key' configuration parameter.

				Log << DEBUG << "Checking if 'tls_key' parameter exists... ";

				if( Cfg.Exists( "tls_key" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'tls_key' is: '" << Cfg.GetValue( "tls_key" ) << "'" << endl;
					Log << DEBUG << "Checking if '" << Cfg.GetValue( "tls_key" ) << "' exists... "; 

					if( ACCESS_F( Cfg.GetValue( "tls_key" ).c_str() ) )
					{
						Log << "Yes." << endl;
						Log << DEBUG << "Checking if '" << Cfg.GetValue( "tls_key" ) << "' is readable...";

						if( ACCESS_R( Cfg.GetValue( "tls_key" ).c_str() ) )
						{
							Log << "Yes." << endl;

							if( ( ErrorCode = ldap_set_option( LDAPInterface,
							                                   LDAP_OPT_X_TLS_KEYFILE,
							                                   Cfg.GetValue( "tls_key" ).c_str() ) ) != LDAP_SUCCESS )
							{
								Log << WARNING << "ldap_set_option( TLS_KEY ): " << ldap_err2string( ErrorCode ) << ". "
								                  "Attempting to continue." << endl;
							}
							else
							{
								Log << INFORMATION << "ldap_set_option( TLS_KEY ): Success." << endl;
							}
						}
						else
						{
							Log << "No." << endl;
							Log << WARNING << "ldap_set_option( TLS_KEY ): " << ErrnoToString() << ". Attempting to continue."
							               << endl;
						}
					}
					else
					{
						Log << "No." << endl;
						Log << WARNING << "ldap_set_option( TLS_KEY ): " << ErrnoToString() << ". Attempting to continue." << endl;
					}
				}
				else
				{
					Log << "No." << endl;
				}

			// Set LDAP_OPT_X_TLS_CIPHER_SUITE using 'tls_ciphers' configuration parameter.

				Log << DEBUG << "Checking if 'tls_ciphers' parameter exists... ";

				if( Cfg.Exists( "tls_ciphers" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'tls_ciphers' is: '" << Cfg.GetValue( "tls_ciphers" ) << "'" << endl;

					if( ( ErrorCode = ldap_set_option( LDAPInterface,
					                                   LDAP_OPT_X_TLS_CIPHER_SUITE,
					                                   Cfg.GetValue( "tls_ciphers" ).c_str() ) ) != LDAP_SUCCESS )
					{
						Log << WARNING << "ldap_set_option( TLS_CIPHERS ): " << ldap_err2string( ErrorCode ) << ". Attempting to "
						                  "continue." << endl;
					}
					else
					{
						Log << INFORMATION << "ldap_set_option( TLS_CIPHERS ): Success." << endl;
					}
				}
				else
				{
					Log << "No." << endl;
				}

			// Set LDAP_OPT_X_TLS_DHFILE using 'tls_dhfile' configuration parameter.

				Log << DEBUG << "Checking if 'tls_dhfile' parameter exists... ";

				if( Cfg.Exists( "tls_dhfile" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'tls_dhfile' is: '" << Cfg.GetValue( "tls_dhfile" ) << "'" << endl;
					Log << DEBUG << "Checking if '" << Cfg.GetValue( "tls_dhfile" ) << "' exists... "; 

					if( ACCESS_F( Cfg.GetValue( "tls_dhfile" ).c_str() ) )
					{
						Log << "Yes." << endl;
						Log << DEBUG << "Checking if '" << Cfg.GetValue( "tls_dhfile" ) << "' is readable...";

						if( ACCESS_R( Cfg.GetValue( "tls_dhfile" ).c_str() ) )
						{
							Log << "Yes." << endl;

							if( ( ErrorCode = ldap_set_option( LDAPInterface,
							                                   LDAP_OPT_X_TLS_DHFILE,
							                                   Cfg.GetValue( "tls_dhfile" ).c_str() ) ) != LDAP_SUCCESS )
							{
								Log << WARNING << "ldap_set_option( TLS_DHFILE ): " << ldap_err2string( ErrorCode ) << ". "
								                  "Attempting to continue." << endl;
							}
							else
							{
								Log << INFORMATION << "ldap_set_option( TLS_DHFILE ): Success." << endl;
							}
						}
						else
						{
							Log << "No." << endl;
							Log << WARNING << "ldap_set_option( TLS_DHFILE ): " << ErrnoToString() << ". Attempting to continue."
							               << endl;
						}
					}
					else
					{
						Log << "No." << endl;
						Log << WARNING << "ldap_set_option( TLS_DHFILE ): " << ErrnoToString() << ". Attempting to continue."
						               << endl;
					}
				}
				else
				{
					Log << "No." << endl;
				}

			// Set LDAP_OPT_X_TLS_RANDOM_FILE using 'tls_randfile' configuration parameter.

				Log << DEBUG << "Checking if 'tls_randfile' parameter exists... ";

				if( Cfg.Exists( "tls_randfile" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'tls_randfile' is: '" << Cfg.GetValue( "tls_randfile" ) << "'" << endl;
					Log << DEBUG << "Checking if '" << Cfg.GetValue( "tls_randfile" ) << "' exists... ";

					if( ACCESS_F( Cfg.GetValue( "tls_randfile" ).c_str() ) )
					{
						Log << "Yes." << endl;
						Log << DEBUG << "Checking if '" << Cfg.GetValue( "tls_randfile" ) << "' is readable... ";

						if( ACCESS_R( Cfg.GetValue( "tls_randfile" ).c_str() ) )
						{
							Log << "Yes." << endl;

							if( ( ErrorCode = ldap_set_option( LDAPInterface,
							                                   LDAP_OPT_X_TLS_RANDOM_FILE,
							                                   Cfg.GetValue( "tls_randfile" ).c_str() ) ) != LDAP_SUCCESS )
							{
								Log << WARNING << "ldap_set_option( TLS_RANDFILE ): " << ldap_err2string( ErrorCode ) << ". "
								                  "Attempting to continue." << endl;
							}
							else
							{
								Log << INFORMATION << "ldap_set_option( TLS_RANDFILE ): Success." << endl;
							}
						}
						else
						{
							Log << "No." << endl;
							Log << WARNING << "ldap_set_option( TLS_RANDFILE ): " << ErrnoToString() << ". Attempting to "
							                  "continue." << endl;
						}
					}
					else
					{
						Log << "No." << endl;
						Log << WARNING << "ldap_set_option( TLS_RANDFILE ): " << ErrnoToString() << ". Attempting to continue."
						               << endl;
					}
				}
				else
				{
					Log << "No." << endl;
				}

			// Set LDAP_OPT_X_TLS_REQUIRE_CERT using 'tls_reqcert' configuration parameter.

				Log << DEBUG << "Checking if 'tls_reqcert' parameter exists... ";

				if( Cfg.Exists( "tls_reqcert" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'tls_reqcert' is: '" << Cfg.GetValue( "tls_reqcert" ) << "'" << endl;

					StringValue = Cfg.GetValue( "tls_reqcert" );

					try
					{
						transform( StringValue.begin(), StringValue.end(), StringValue.begin(), ::tolower );
					}
					catch( bad_alloc& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'tls_reqcert' parameter cannot be parsed. '" << Exception.what() << "' : " 
						               << ErrnoToString( ENOMEM ) << ". Attempting to continue." << endl;
					}
					catch( exception& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'tls_reqcert' parameter cannot be parsed. '" << Exception.what() << "' threw an"
						                  "unhandled exception. Attempting to continue." << endl;
					}

					if( !ErrorOccurred )
					{
						if( StringValue == "never" )
						{
							IntegerValue = LDAP_OPT_X_TLS_NEVER;
						}
						else if( StringValue == "allow" )
						{
							IntegerValue = LDAP_OPT_X_TLS_ALLOW;
						}
						else if( StringValue == "try" )
						{
							IntegerValue = LDAP_OPT_X_TLS_TRY;
						}
						else if( StringValue == "demand" )
						{
							IntegerValue = LDAP_OPT_X_TLS_DEMAND;
						}
						else if( StringValue == "hard" )
						{
							IntegerValue = LDAP_OPT_X_TLS_HARD;
						}
						else
						{
							ErrorOccurred = true;
							Log << WARNING << "Value of 'tls_reqcert' parameter is invalid. Attempting to continue." << endl;
						}

						if( !ErrorOccurred )
						{
							if( ( ErrorCode = ldap_set_option( LDAPInterface,
							                                   LDAP_OPT_X_TLS_REQUIRE_CERT,
							                                   &IntegerValue ) ) != LDAP_SUCCESS )
							{
								Log << WARNING << "ldap_set_option( TLS_REQCERT ): " << ldap_err2string( ErrorCode ) << ". "
								                  "Attempting to continue." << endl;
							}
							else
							{
								Log << INFORMATION << "ldap_set_option( TLS_REQCERT ): Success." << endl;
							}
						}
						else
						{
							ErrorOccurred = false;
						}
					}
					else
					{
						ErrorOccurred = false;
					}
				}
				else
				{
					Log << "No." << endl;
				}

			// Set LDAP_OPT_X_TLS_CRLCHECK using 'tls_crlcheck' configuration parameter.

				Log << DEBUG << "Checking if 'tls_crlcheck' parameter exists... ";

				if( Cfg.Exists( "tls_crlcheck" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'tls_crlcheck' is: '" << Cfg.GetValue( "tls_crlcheck" ) << "'" << endl;

					StringValue = Cfg.GetValue( "tls_crlcheck" );

					try
					{
						transform( StringValue.begin(), StringValue.end(), StringValue.begin(), ::tolower );
					}
					catch( bad_alloc& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'tls_crlcheck' parameter cannot be parsed. '" << Exception.what() << "' : "
						               << ErrnoToString( ENOMEM ) << ". Attempting to continue." << endl;
					}
					catch( exception& Exception )
					{
						ErrorOccurred = true;
						Log << WARNING << "Value of 'tls_crlcheck' parameter cannot be parsed. '" << Exception.what() << "' threw an"
						                  "unhandled exception. Attempting to continue." << endl;
					}

					if( !ErrorOccurred )
					{
						if( StringValue == "none" )
						{
							IntegerValue = LDAP_OPT_X_TLS_CRL_NONE;
						}
						else if( StringValue == "peer" )
						{
							IntegerValue = LDAP_OPT_X_TLS_CRL_PEER;
						}
						else if( StringValue == "all" )
						{
							IntegerValue = LDAP_OPT_X_TLS_CRL_ALL;
						}
						else
						{
							ErrorOccurred = true;
							Log << WARNING << "Value of 'tls_crlcheck' parameter is invalid. Attempting to continue." << endl;
						}

						if( !ErrorOccurred )
						{
							if( ( ErrorCode = ldap_set_option( LDAPInterface,
							                                   LDAP_OPT_X_TLS_CRLCHECK,
							                                   &IntegerValue ) ) != LDAP_SUCCESS )
							{
								Log << WARNING << "ldap_set_option( TLS_CRLCHECK ): " << ldap_err2string( ErrorCode ) << ". "
								                  "Attempting to continue." << endl;
							}
							else
							{
								Log << INFORMATION << "ldap_set_option( TLS_REQCERT ): Success." << endl;
							}
						}
						else
						{
							ErrorOccurred = false;
						}
					}
					else
					{
						ErrorOccurred = false;
					}
				}
				else
				{
					Log << "No." << endl;
				}

			// Upgrade to TLS connection if 'start_tls' configuration parameter is set to a variation of 'true'.

				Log << DEBUG << "Checking if 'start_tls' parameter exists... ";

				if( Cfg.Exists( "start_tls" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'start_tls' is: '" << Cfg.GetValue( "start_tls" ) << "'" << endl;
					Log << DEBUG << "Checking if 'start_tls' parameter is a variation of 'true'... ";

					StringValue = Cfg.GetValue( "start_tls" );

					try
					{
						transform( StringValue.begin(), StringValue.end(), StringValue.begin(), ::tolower );
					}
					catch( bad_alloc& Exception )
					{
						ErrorOccurred = true;
						Log << endl << WARNING << "Value of 'start_tls' parameter cannot be parsed. '" << Exception.what() << "' : "
						                       << ErrnoToString( ENOMEM ) << ". Attempting to continue." << endl;
					}
					catch( exception& Exception )
					{
						ErrorOccurred = true;
						Log << endl << WARNING << "Value of 'start_tls' parameter cannot be parsed. '" << Exception.what() << "' threw"
						                          " an unhandled exception. Attempting to continue." << endl;
					}

					if( !ErrorOccurred )
					{
						if( ( StringValue == "true" ) ||
						    ( StringValue == "t" ) ||
						    ( StringValue == "yes" ) ||
						    ( StringValue == "y" ) ||
						    ( StringValue == "enable" ) ||
						    ( StringValue == "enabled ") ||
						    ( StringValue == "on" ) )
						{
							Log << "Yes." << endl;

							ErrorCode = ldap_start_tls_s( LDAPInterface, nullptr, nullptr );

							if( ErrorCode != LDAP_SUCCESS )
							{
								ldap_get_option( LDAPInterface, LDAP_OPT_DIAGNOSTIC_MESSAGE, &ErrorMessageBuffer );
								ErrorMessage = string( ErrorMessageBuffer );

								FreeMemory();

								Log << CRITICAL << "ldap_start_tls_s(): " << ldap_err2string( ErrorCode ) << " : "
								                << ErrorMessage << ". Cannot continue." << endl;
							}
							else
							{
								Log << INFORMATION << "ldap_start_tls_s(): Success." << endl;
							}
						}
						else
						{
							Log << "No." << endl;
						}
					}
					else
					{
						ErrorOccurred = false;
					}
				}
				else
				{
					Log << "No." << endl;
				}

			// Bind using credentials supplied via 'binddn' and 'bindpw' configuration parameters, or anonymous bind.

				Log << DEBUG << "Checking if 'binddn' parameter exists... ";

				// TODO: Add options for other SASL mechanisms. Also Kerberos.
				if( Cfg.Exists( "binddn" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'binddn' is: '" << Cfg.GetValue( "binddn" ) << "'" << endl;
					Log << DEBUG << "Checking if 'bindpw' parameter exists... ";

					if( Cfg.Exists( "bindpw" ) )
					{
						Log << "Yes." << endl;
						Log << DEBUG << "The value of 'bindpw' is: " << Cfg.GetValue( "bindpw" ) << endl;
						Log << DEBUG << "Note: Please redact the 'bindpw' value when submitting logs (it also appears in the "
						                "configuration dump above)." << endl;
						Log << INFORMATION << "Attempting authenticated bind..." << endl;

						Credentials = ber_bvstrdup( Cfg.GetValue( "bindpw" ).c_str() );

						ErrorCode = ldap_sasl_bind_s( LDAPInterface,
									Cfg.GetValue( "binddn" ).c_str(),
									LDAP_SASL_SIMPLE,
									Credentials,
									nullptr,
									nullptr,
									&ServerCredentials );

						BerValueFree( Credentials );
					}
					else
					{
						Log << "No." << endl;

						ErrorCode = LDAP_INVALID_CREDENTIALS;
					}
				}
				else
				{
					Log << "No." << endl;
					Log << INFORMATION << "Attempting anonymous bind..." << endl;

					Credentials = ber_bvstrdup( "" );

					ErrorCode = ldap_sasl_bind_s( LDAPInterface,
					                              nullptr,
					                              LDAP_SASL_SIMPLE,
					                              Credentials,
					                              nullptr,
					                              nullptr,
					                              &ServerCredentials );

					BerValueFree( Credentials );
				}

			// On bind error, log error to syslog and exit on failure.

				if( ErrorCode != LDAP_SUCCESS )
				{
					FreeMemory();

					Log << CRITICAL << "ldap_sasl_bind_s(): " << ldap_err2string( ErrorCode ) << ". Cannot continue." << endl;
				}
				else
				{
					Log << INFORMATION << "ldap_sasl_bind_s(): Success." << endl;
				}

			// Set scope from configuration value (only accepts "one" or "sub"; "base" is ignored) or default to LDAP_SCOPE_ONELEVEL.

				Log << DEBUG << "Checking if 'scope' parameter exists... ";

				if( Cfg.Exists( "scope" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'scope' is: '" << Cfg.GetValue( "scope" ) << "'" << endl;

					if( ( Cfg.GetValue( "scope" ) == "one" ) || ( Cfg.GetValue( "scope" ) == "onelevel" ) )
					{
						Scope = LDAP_SCOPE_ONELEVEL;
					}
					else if( ( Cfg.GetValue( "scope" ) == "sub" ) || ( Cfg.GetValue( "scope" ) == "subtree" ) )
					{
						Scope = LDAP_SCOPE_SUBTREE;
					}
					else
					{
						Log << WARNING << "Value of 'scope' parameter invalid. Defaulting to 'scope' = 'onelevel'." << endl;

						Scope = LDAP_SCOPE_ONELEVEL;
					}
				}
				else
				{
					Log << "No." << endl;
					Log << DEBUG << "Defaulting to 'scope' = 'onelevel'." << endl;

					Scope = LDAP_SCOPE_ONELEVEL;
				}

			// Set filter from configuration value and argv[1] (%1 denotes username and is replaced by argv[1]).

				Log << DEBUG << "Checking if 'filter' parameter exists... ";

				if( Cfg.Exists( "filter" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'filter' is: '" << Cfg.GetValue( "filter" ) << "'" << endl;

					Filter = Cfg.GetValue( "filter" );
					FindPosition = Filter.find( "%1" );

					if( FindPosition == string::npos )
					{
						FreeMemory();

						Log << CRITICAL << " Value of 'filter' parameter invalid. '%1' must denote username in filter." << endl;
					}

					Filter.replace( FindPosition, 2, Username );
				}
				else
				{
					Log << "No." << endl;
					Log << DEBUG << "Defaulting to 'filter' = 'cn=%1'" << endl;

					Filter = "cn=" + Username;
				}

			// Copy attribute name from configuration value or default to the default attribute name, "sshPublicKey".

				Log << DEBUG << "Checking if 'attribute' parameter exists... ";

				if( Cfg.Exists( "attribute" ) && ( !Cfg.GetValue( "attribute" ).empty() ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'attribute' is: '" << Cfg.GetValue( "attribute" ) << "'" << endl;

					AttributeName = Cfg.GetValue( "attribute" );
				}
				else
				{
					Log << "No." << endl;
					Log << DEBUG << "Defaulting to 'attribute' = 'sshPublicKey'" << endl;

					AttributeName = "sshPublicKey";
				}

			// Check if 'base' parameter exists in configuration file.

				Log << DEBUG << "Checking if 'base' parameter exists...";

				if( Cfg.Exists( "base" ) )
				{
					Log << "Yes." << endl;
					Log << DEBUG << "The value of 'base' is: '" << Cfg.GetValue( "base" ) << "'" << endl;

					if( ! regex_match( Cfg.GetValue( "base" ), regex("(\\w+[=]{1}[a-zA-Z0-9\\_\\-\\!\\%\\*\\+\\/\\:\\;\\<\\>\\?\\$\\&\\#"
					                                                 "\\(\\)\\[\\]\\{\\}\\.\\s]+)([,{1}]\\w+[=]{1}[a-zA-Z0-9\\_\\-\\!\\%"
					                                                 "\\*\\+\\/\\:\\;\\<\\>\\?\\$\\&\\#\\(\\)\\[\\]\\{\\}\\.\\s]+)*") ) )
					{
						FreeMemory();

						Log << CRITICAL << "Value of 'bind' parameter invalid." << endl;
					}
				}
				else
				{
					Log << "No." << endl;

					FreeMemory();

					Log << CRITICAL << "Value of 'bind' parameter undefined." << endl;
				}

			// Convert attribute name to a NULL-terminated c-string array for ldap_search_ext_s().

				AttributeListLength = 2;
				AttributeList = new char*[ AttributeListLength ];
				AttributeList[ 0 ] = new char[ AttributeName.length() + 1 ];
				strcpy( AttributeList[ 0 ], AttributeName.c_str() );
				AttributeList[ 1 ] = nullptr;

			// Commit search. Note: Fetch a maximum 2 entries to ensure the entry is singular.

				Log << DEBUG << "Performing search... ";

				ErrorCode = ldap_search_ext_s( LDAPInterface,
				                               Cfg.GetValue( "base" ).c_str(),
				                               Scope,
				                               Filter.c_str(),
				                               AttributeList,
				                               0,
				                               nullptr,
				                               nullptr,
				                               nullptr,
				                               2, 
				                               &Response );

				Log << "Finished." << endl;

			// Free attribute name c-string array.

				CStringArrayFree( AttributeList, AttributeListLength );

			// If an error occurred, log error and exit on failure.

				if( ErrorCode != LDAP_SUCCESS )
				{
					FreeMemory();

					Log << CRITICAL << "ldap_search_ext_s(): " << ldap_err2string( ErrorCode ) << ". Cannot continue." << endl;
				}

			// Ensure the entry is singular or log error and exit on failure; also exit on zero entries.

				Log << DEBUG << "Number of entries in result: " << ldap_count_entries( LDAPInterface, Response ) << "." << endl;

				if( ldap_count_entries( LDAPInterface, Response ) > 1 )
				{
					FreeMemory();

					Log << CRITICAL << "Filter returned more than one result for user: " << Username << endl;
				}
				else if( ldap_count_entries( LDAPInterface, Response ) == 0 )
				{
					FreeMemory();

					Log << INFORMATION << "No results returned for user: " << Username << "." << endl;

					return 0; // << remove this later...
				}

			// Set a pointer to the entry.

				Entry = ldap_first_entry( LDAPInterface, Response );

			// Loop through attributes. Send the returned value matching attribute name (above) to stdout.

				AttributeCount = 0;

				for( Attribute = ldap_first_attribute( LDAPInterface, Entry, &AttributeIterator );
				;
				Attribute = ldap_next_attribute( LDAPInterface, Entry, AttributeIterator ) )
				{
					if( Attribute == NULL )
					{
						break;
					}
					else if( string( Attribute ) == AttributeName )
					{
						Values = ldap_get_values_len( LDAPInterface, Entry, Attribute );

						Log << DEBUG << "Number of attribute values in result: " << ldap_count_values_len( Values ) << "." << endl;

						for( ValueIndex = 0; ValueIndex < ldap_count_values_len( Values ); ValueIndex++ )
							cout << Values[ ValueIndex ]->bv_val << endl;
						
						LDAPValueFreeLen( Values );
						LDAPMemFree( Attribute );
					}
					else
					{ 
						LDAPMemFree( Attribute );
					}

					AttributeCount++;
				}

				Log << DEBUG << "Number of attributes in result: " << AttributeCount << "." << endl;
				Log << INFORMATION << "Success for user: " << Username << "." << endl;

		}
		catch( out_of_range& Exception )
		{
			FreeMemory();
			Log << endl << CRITICAL << Exception.what() << " : " << ErrnoToString( ERANGE ) << "." << endl;
		}
		catch( length_error& Exception )
		{
			FreeMemory();
			Log << endl << CRITICAL << Exception.what() << " : " << ErrnoToString( EOVERFLOW ) << "." << endl;
		}
		catch( ios_base::failure& Exception )
		{
			FreeMemory();
			Log << endl << CRITICAL << Exception.what() << " : " << ErrnoToString( EIO ) << "." << endl;
		}
		catch( bad_alloc& Exception )
		{
			FreeMemory();
			Log << endl << CRITICAL << Exception.what() << " : " << ErrnoToString( ENOMEM ) << "." << endl;
		}
		catch( invalid_argument& Exception )
		{
			FreeMemory();
			Log << endl << CRITICAL << Exception.what() << " : " << ErrnoToString( EINVAL ) << "." << endl;
		}
		catch( exception& Exception )
		{
			FreeMemory();
			Log << endl << CRITICAL << Exception.what() <<" : " << ErrnoToString( EBADMSG ) << "." << endl;
		}

	// Free memory and close LDAP.

		FreeMemory();

	// Return on success.

		return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// End of 'LSSHKeys.cpp'
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////