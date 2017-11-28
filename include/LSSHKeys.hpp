////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// LSSHKeys.hpp
// Matthew J. Schultz | Created : 31OCT17 | Last Modified : 31OCT17 by Matthew J. Schultz
// Version : 0.0.1
// This is the main header file for 'LSSHKeys', a program to fetch SSH Public Keys from an LDAP directory.
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

#ifndef __QMX_LSSHKEYS_HPP_
#define __QMX_LSSHKEYS_HPP_

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Header Files
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

extern "C"
{
#	include <ldap.h>
#	include <syslog.h>
#	include <unistd.h>
#	include <libgen.h>
}

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <locale>
#include <map>
#include <queue>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <utility>

#include "../build/Config.hpp"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Static Macros
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define EMERGENCY   Output::Level::Emergency
#define ALERT       Output::Level::Alert
#define CRITICAL    Output::Level::Critical
#define ERROR       Output::Level::Error
#define WARNING     Output::Level::Warning
#define NOTICE      Output::Level::Notice
#define INFORMATION Output::Level::Information
#define DEBUG       Output::Level::Debug

#define ACCESS(x,y) ( access( x, y ) == 0 )
#define ACCESS_F(x) ACCESS( x, F_OK )
#define ACCESS_X(x) ACCESS( x, X_OK )
#define ACCESS_R(x) ACCESS( x, R_OK )
#define ACCESS_W(x) ACCESS( x, W_OK )

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The 'Utility' Namespace
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace Utility
{
	// Member Methods.

		std::string ErrnoToString()
		{
			// Return ReturnValue.

				return std::string( strerror( errno ) );
		}

		std::string ErrnoToString( int ErrorNumber )
		{
			// return ReturnValue.

				return std::string( strerror( ErrorNumber ) );
		}

		void PreLogCritical( std::string Message )
		{
			// Open syslog, log critical message, then close syslog.

				openlog( NAME, LOG_ODELAY, LOG_AUTH );
				syslog( LOG_CRIT, "%s. Aborting.", Message.c_str());
				closelog();

			// Log critical message to stderr.

				std::cerr << "[ Critical ] : " << Message << ". Aborting." << std::endl;

			// Call exit() with failure status.

				exit( EXIT_FAILURE );
		}

		void LDAPClose( LDAP*& Object )
		{
			// Unbind LDAP interface and free memory.

				ldap_unbind_ext_s( Object, nullptr, nullptr );

			// Set pointer to null.

				Object = nullptr;
		}

		void LDAPMemFree( char*& Object )
		{
			// Free memory allocated by LDAP.

				ldap_memfree( Object );

			// Set pointer to null.

				Object = nullptr;
		}

		void LDAPMsgFree( LDAPMessage*& Object )
		{
			// Free LDAP message.

				ldap_msgfree( Object );

			// Set pointer to null.

				Object = nullptr;
		}

		void LDAPValueFreeLen( BerValue**& Object )
		{
			// Free memory allocated by LDAP.

				ldap_value_free_len( Object );

			// Set pointer to null.

				Object = nullptr;
		}

		void BerFree( BerElement*& Object )
		{
			// Free BerElement memory.

				ber_free( Object, 0 );

			// Set pointer to null.

				Object = nullptr;
		}

		void BerValueFree( BerValue*& Object )
		{
			// Free BerValue memory.

				ber_bvfree( Object );

			// Set pointer to null.

				Object = nullptr;
		}

		void CStringFree( char*& Object )
		{
			// Free cstring memory.

				delete[] Object;

			// Set pointer to null.

				Object = nullptr;
		}

		void CStringArrayFree( char**& Object, size_t ObjectSize )
		{
			// Free cstring array element memory.

				for( size_t Index = 0; Index < ObjectSize; Index++ )
					delete[] Object[ Index ];

			// Free cstring array memory.

				delete[] Object;

			// Set pointer to null.

				Object = nullptr;
		}
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The 'Config' Class
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class Config 
{

public:

	// Public Methods
		void Init()
		{
			// Initialize using default configuration file.

				std::ifstream File( CONFIG );
				Init( File );
		}

		void Init( std::ifstream& File )
		{
			// Create local variables.

				char CurrentSymbol;
				bool Comment = false;
				std::string Buffer;
				std::string Key;
				std::string Value;

			// Ensure our file is open.

				if( !File.is_open() )
				{
					throw std::ios_base::failure( "Cannot open configuration file" );
				}

			// Parse contents of configuration file and store in configuration map.

				while( File.good() )
				{
					CurrentSymbol = File.get();

					if( CurrentSymbol == '#' )
					{
						Comment = true;
					}
					else if( ( ( CurrentSymbol == '\t' ) || ( CurrentSymbol == ' ') ) && ( !Comment ))
					{
						Key = Buffer;
						Buffer.clear();
					}
					else if( CurrentSymbol == '\n' )
					{
						if( !Comment )
						{
							if ( !Buffer.empty() )
							{
								Value = Buffer;
								Buffer.clear();
								ConfigurationMap.insert( make_pair( Key, Value ) );
							}
						}
						else
							Comment = false;
					}
					else
					{
						if( !Comment )
							Buffer.push_back( CurrentSymbol );
					}

				}
		}

		bool Exists( const std::string Key )
		{

			// Create local variables.

				bool ReturnValue;
				std::map< std::string, std::string >::iterator Iterator;

			// Search for 'key' in the configuration map.

				Iterator = ConfigurationMap.find( Key );

			// Return true if 'key' is found.

				if( Iterator != ConfigurationMap.end() )
					ReturnValue = true;
				else
					ReturnValue = false;

			// Return ReturnValue.

				return ReturnValue;
		}

		std::string GetValue( const std::string Key )
		{
			// Return the value denoted by 'Key' from the configuration map.

				return ConfigurationMap[ Key ];
		}

		int Size()
		{
			// Return the size of the configuration map.

				return ConfigurationMap.size();
		}

		std::map< std::string, std::string > GetConfigurationMap()
		{
			// Return the entire configuration map (for debugging).

				return ConfigurationMap;
		}

private:

	// Private Fields

		std::map< std::string, std::string > ConfigurationMap;

};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The 'Output' Class
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class Output : public std::ostream, std::streambuf
{

public:

	// Public Data Types

		enum Level
		{
			Emergency = LOG_EMERG,
			Alert = LOG_ALERT,
			Critical = LOG_CRIT,
			Error = LOG_ERR,
			Warning = LOG_WARNING,
			Notice = LOG_NOTICE,
			Information = LOG_INFO,
			Debug = LOG_DEBUG
		};

		enum Method
		{
			Syslog,
			Stdio,
			File
		};

	// Destructor

		~Output()
		{
			// Perform necessary cleanup.

				if( Active )
				{
					if( Facility == Method::Syslog )
					{
						closelog();
					} 
					else if( Facility == Method::File )
					{
						if( LogFile->is_open() )
							LogFile->close();
					}
					Active = false;
				}
		}

	// Public Methods

		void Init( const Method LogMethod, const Level OutputLevel )
		{
			// Set field values.

				CurrentLevel = Level::Notice;
				MinimumLevel = OutputLevel;

			// Select Facility; error to syslog and cerr then exit if invalid.

				switch( LogMethod )
				{
					case Method::Syslog:
					{
						Facility = Method::Syslog;
						openlog( NAME, LOG_ODELAY, LOG_AUTH );
						break;
					}
					case Method::Stdio:
					{
						Facility = Method::Stdio;
						break;
					}
					default:
					{
						throw std::out_of_range( "Invalid log type." );
					}
				}

			// Set the Active field value to true.

				Active = true;
		}

		void Init( std::ofstream& File, const Level OutputLevel )
		{
			// Set field values.

				CurrentLevel = Level::Notice;
				MinimumLevel = OutputLevel;
				Facility = Method::File;

			// Ensure log filestream is open; error to syslog and cerr then exit if it is not.

				if( !File.is_open() )
				{
					throw std::ios_base::failure( "Cannot open log file for writing" );
				}

			// Initialize the pointer to the filestream and set the active field value to true.

				LogFile = &File;
				Active = true;
		}

	// Public Overloaded Operators

		Output& operator<<( const Level LogLevel )
		{
			// Set CurrentLevel to incoming LogLevel.

				CurrentLevel = LogLevel;

			// Return pointer to this object.

				return *this;
		}

		Output& operator<<( const std::string& s )
		{
			// Append incoming string to Buffer.

				Buffer.append(s);

			// Return pointer to this object.

				return *this;
		}

		Output& operator<<( const char* s )
		{
			// Append incoming cstring to Buffer.

				Buffer.append(s);

			// Return pointer to this object.

				return *this;
		}

		Output& operator<<( const char& c )
		{
			// Push incoming char onto Buffer.

				Buffer.push_back(c);

			// Return pointer to this object.

				return *this;
		}

		template < typename T, typename = typename std::enable_if< std::is_arithmetic< T >::value, T >::type >
		Output& operator<<( const T& NumericValue )
		{
			// Create local stringstream.

				std::stringstream ValueStream;

			// Unset floatfield flag for stringstream (is this necessary?)

				// ValueStream.unsetf( ios_base::floatfield );

			// Stream numeric value to local stringstream with precision based on its type.

				ValueStream << std::setprecision( std::numeric_limits< T >::digits10 ) << NumericValue;

			// Append stringstream to Buffer.

				Buffer.append( ValueStream.str() );

			// Return pointer to this object.

				return *this;
		}

		typedef std::ostream& ( *OStreamManipulator )( std::ostream& );
		Output& operator<<( OStreamManipulator Object )
		{
			// Push newline character onto buffer.

				Buffer.push_back( '\n' );

			// Call sync().

				sync();

			// Set current level back to its default value.

				CurrentLevel = Level::Notice;

			// Return pointer to this object.

				return *this;
		}

private:

	// Private Fields

		bool Active;
		std::ofstream* LogFile;
		std::string Buffer;
		Level CurrentLevel;
		Level MinimumLevel;
		Method Facility;

	// Private Methods

		int sync()
		{
			// Create local variables

				std::string LogLevelLabel;
				time_t CurrentTime = std::chrono::system_clock::to_time_t( std::chrono::system_clock::now() );
				tm CurrentTimeLocal = *std::localtime( &CurrentTime );

			// Perform output logic. Add level token to output for stdout and time + level token for filestream.
			// On a critical level or above, exit. Also error and exit if level or facility are invalid.

				if( ( !Buffer.empty() ) && ( !( Buffer == "\n" ) ) )
				{
					switch( CurrentLevel )
					{
						case Level::Emergency:
						{
							LogLevelLabel = "[ Emergency ] : ";
							break;
						}

						case Level::Alert:
						{
							LogLevelLabel = "[ Alert ] : ";
							break;
						}

						case Level::Critical:
						{
							LogLevelLabel = "[ Critical ] : ";
							break;
						}

						case Level::Error:
						{
							LogLevelLabel = "[ Error ] : ";
							break;
						}

						case Level::Warning:
						{
							LogLevelLabel = "[ Warning ] : ";
							break;
						}

						case Level::Notice:
						{
							LogLevelLabel = "[ Notice ] : ";
							break;
						}

						case Level::Information:
						{
							LogLevelLabel = "[ Information ] : ";
							break;
						}

						case Level::Debug:
						{
							LogLevelLabel = "[ Debug ] : ";
							break;
						}

						default:
						{
							throw std::out_of_range( "Internal error: Previously qualified log level value is invalid at line 607"
							                         " of 'LSSHKeys.hpp'. Please file a bug report");
						}
						
					}

					if( CurrentLevel <= MinimumLevel )
					{
						switch( Facility )
						{
							case Method::Syslog:
							{
								if ( CurrentLevel <= Level::Warning )
									std::cerr << LogLevelLabel << Buffer;

								syslog( CurrentLevel, "%s", Buffer.c_str() );

								break;
							}

							case Method::Stdio:
							{
								std::cerr << LogLevelLabel << Buffer;

								break;
							}

							case Method::File:
							{
								if ( CurrentLevel <= Level::Warning )
									std::cerr << LogLevelLabel << Buffer;

								*LogFile << "[ " 
								         << std::put_time( &CurrentTimeLocal, "%Y-%m-%d %H:%M:%S %z" ) 
								         << " ] " 
								         << LogLevelLabel 
								         << Buffer;

								break;
							}

							default:
							{
								throw std::out_of_range( "Internal error: Previously qualified log type value is invalid at "
								                         "line 650 of 'LSSHKeys.hpp'. Please file a bug report.");
							}
						}
					}

					Buffer.clear();

					if( CurrentLevel <= Level::Critical )
						SafeExit( EXIT_FAILURE );
				}
				else
				{
					if ( Buffer == "\n" )
						Buffer.clear();
				}
			
			// Return on success.

				return 0;
		}

		void SafeExit( int ExitCode )
		{
			// Perform necessary cleanup.

				if( Active )
				{
					if( Facility == Method::Syslog )
					{
						closelog();
					} 
					else if( Facility == Method::File )
					{
						if( LogFile->is_open() )
							LogFile->close();
					}
					Active = false;
				}

			// Call exit() with given exit code.

				exit( ExitCode );
		}
};

#endif // __QMX_LSSHKEYS_HPP_

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// End of 'LSSHKeys.hpp'
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////