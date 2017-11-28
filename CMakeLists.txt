################################################################################################################################################################
# CMakeLists.txt
# Robert M. Baker | Created : 31OCT17 | Last Modified : 28NOV17 by Matthew J. Schultz
# Version : 0.0.1
# This is a CMake script for building 'LSSHKeys'.
################################################################################################################################################################
# Copyright (C) 2017 QuantuMatriX Software, a QuantuMatriX Technologies Cooperative Partnership
#
# This file is part of 'LSSHKeys'.
#
# 'LSSHKeys' is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any later version.
#
# 'LSSHKeys' is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License along with 'LSSHKeys'.  If not, see <http://www.gnu.org/licenses/>.
################################################################################################################################################################

# TODO (Malachy - Priority 50): Complete and test for Apple macOS platform.

################################################################################################################################################################
# Environment Check
################################################################################################################################################################

# General

cmake_minimum_required( VERSION 3.9.3 )

if( NOT "${CMAKE_BINARY_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}/build" )
	message( FATAL_ERROR "You must build the project from '${CMAKE_SOURCE_DIR}/build'!  See 'README.md' for build instructions." )
endif()

project( PROJECT VERSION 1.0.0 LANGUAGES C CXX )

# Project-Specific

if( NOT ${CMAKE_SYSTEM_NAME} STREQUAL "Windows" )
	find_path( LDAP_INCLUDE_DIR ldap.h )
   find_library( LDAP_LIBRARIES NAMES ldap )
   find_library( LBER_LIBRARIES NAMES lber )
else()
	message( FATAL_ERROR "LSSHKeys is not supported on this platform!" )
endif()

if( NOT LDAP_INCLUDE_DIR AND LDAP_LIBRARIES AND LBER_LIBRARIES )
	message( FATAL_ERROR "LDAP libraries not found!" )
endif()

################################################################################################################################################################
# Setup
################################################################################################################################################################

# Project Info

set( PROJECT_TARGET "lsshkeys" )

# General

include( CMakePackageConfigHelpers )
set( CMAKE_SKIP_INSTALL_ALL_DEPENDENCY true )
set( COMPILE_FLAGS_DEBUG "-g -Wall -Wno-unknown-warning-option -Wno-maybe-uninitialized -Wno-attributes -D_DEBUG"
     CACHE STRING "These are the debug compile flags." )
set( COMPILE_FLAGS_RELWITHDEBINFO "-O2 -g -Wall -Wno-unknown-warning-option -Wno-maybe-uninitialized -Wno-attributes -DNDEBUG"
     CACHE STRING "These are the release with debug info compile flags." )
set( COMPILE_FLAGS_RELEASE "-O3 -Wall -Wno-unknown-warning-option -Wno-maybe-uninitialized -Wno-attributes -DNDEBUG"
     CACHE STRING "These are the release compile flags." )
set( COMPILE_FLAGS_MINSIZEREL "-Os -Wall -Wno-unknown-warning-option -Wno-maybe-uninitialized -Wno-attributes -DNDEBUG"
     CACHE STRING "These are the minimum size release compile flags." )
set( LINK_FLAGS_DEBUG "-z defs"
     CACHE STRING "These are the debug link flags." )
set( LINK_FLAGS_RELWITHDEBINFO "-z defs"
     CACHE STRING "These are the release with debug info link flags." )
set( LINK_FLAGS_RELEASE "-z defs -s"
     CACHE STRING "These are the release link flags." )
set( LINK_FLAGS_MINSIZEREL "-z defs -s"
     CACHE STRING "These are the minimum size release link flags." )
set( PROJECT_BIN_PATH "bin"
     CACHE STRING "This is the path (appended to 'CMAKE_INSTALL_PREFIX') where the binaries will be installed." )
set( PROJECT_MAN_PATH "share/man"
     CACHE STRING "This is the path (appended to 'CMAKE_INSTALL_PREFIX') where the man pages will be installed." )

# Project-Specific

set( CONFIG_FILE "lsshkeys.conf"
     CACHE STRING "This is the name of the project's config file." )
set( CONFIG_PATH "/etc"
     CACHE STRING "This is the path of the project's config file." )
set( PROGRAM_NAME "LSSHKeys"
     CACHE STRING "This is the project's official name." )
set( PROJECT_URL "https://git.qmx-software.com/open-source/lsshkeys"
     CACHE STRING "This is the URL of the project's Git repository." )
set( BUG_URL "https://git.qmx-software.com/open-source/lsshkeys/issues"
     CACHE STRING "This is the URL of the project's bug tracker." )
set( DEFAULT_LOG_LEVEL "5"
     CACHE STRING "This is the default log level for the project." )

set( PROJECT_INCLUDES
     "${LDAP_INCLUDE_DIR}" )
set( PROJECT_SOURCES
     "src/LSSHKeys.cpp" )
set( PROJECT_LIBRARIES_DEBUG
     "${LDAP_LIBRARIES}"
     "${LBER_LIBRARIES}" )
set( PROJECT_LIBRARIES_RELEASE ${PROJECT_LIBRARIES_DEBUG} )

# Configure Files

configure_file( "config/Config.hpp.in" "Config.hpp" )
configure_file( "config/conf.in" "${CONFIG_FILE}" )
configure_file( "config/man.5.in" "${CONFIG_FILE}.5" )
configure_file( "config/man.8.in" "${PROJECT_TARGET}.8" )

################################################################################################################################################################
# Targets
################################################################################################################################################################

# Project

add_executable( debug ${PROJECT_SOURCES} )
target_include_directories( debug PRIVATE ${PROJECT_INCLUDES} )
target_link_libraries( debug ${PROJECT_LIBRARIES_DEBUG} )
set_target_properties( debug PROPERTIES
                       OUTPUT_NAME "${PROJECT_TARGET}_d"
                       COMPILE_FLAGS ${COMPILE_FLAGS_DEBUG}
                       LINK_FLAGS ${LINK_FLAGS_DEBUG} )

add_executable( relwithdebinfo ${PROJECT_SOURCES} )
target_include_directories( relwithdebinfo PRIVATE ${PROJECT_INCLUDES} )
target_link_libraries( relwithdebinfo ${PROJECT_LIBRARIES_RELEASE} )
set_target_properties( relwithdebinfo PROPERTIES
                       EXCLUDE_FROM_ALL true
                       EXCLUDE_FROM_DEFAULT_BUILD true
                       OUTPUT_NAME "${PROJECT_TARGET}"
                       COMPILE_FLAGS ${COMPILE_FLAGS_RELWITHDEBINFO}
                       LINK_FLAGS ${LINK_FLAGS_RELWITHDEBINFO} )

add_executable( release ${PROJECT_SOURCES} )
target_include_directories( release PRIVATE ${PROJECT_INCLUDES} )
target_link_libraries( release ${PROJECT_LIBRARIES_RELEASE} )
set_target_properties( release PROPERTIES
                       OUTPUT_NAME "${PROJECT_TARGET}"
                       COMPILE_FLAGS ${COMPILE_FLAGS_RELEASE}
                       LINK_FLAGS ${LINK_FLAGS_RELEASE} )

add_executable( minsizerel ${PROJECT_SOURCES} )
target_include_directories( minsizerel PRIVATE ${PROJECT_INCLUDES} )
target_link_libraries( minsizerel ${PROJECT_LIBRARIES_RELEASE} )
set_target_properties( minsizerel PROPERTIES
                       EXCLUDE_FROM_ALL true
                       EXCLUDE_FROM_DEFAULT_BUILD true
                       OUTPUT_NAME "${PROJECT_TARGET}"
                       COMPILE_FLAGS ${COMPILE_FLAGS_MINSIZEREL}
                       LINK_FLAGS ${LINK_FLAGS_MINSIZEREL} )

# Installation

install( TARGETS debug RUNTIME DESTINATION "${PROJECT_BIN_PATH}" OPTIONAL )
install( TARGETS release RUNTIME DESTINATION "${PROJECT_BIN_PATH}" OPTIONAL )
install( FILES "build/${CONFIG_FILE}" DESTINATION "${CONFIG_PATH}" )
install( FILES "build/${CONFIG_FILE}.5" DESTINATION "${PROJECT_MAN_PATH}/man5" )
install( FILES "build/${PROJECT_TARGET}.8" DESTINATION "${PROJECT_MAN_PATH}/man8" )
install( CODE "execute_process( COMMAND mandb )" )

# Uninstallation

add_custom_target( uninstall
                   COMMAND ${CMAKE_COMMAND} -E remove "${CMAKE_INSTALL_PREFIX}/${PROJECT_BIN_PATH}/${PROJECT_TARGET}*"
                   COMMAND ${CMAKE_COMMAND} -E remove "${CMAKE_INSTALL_PREFIX}/${PROJECT_MAN_PATH}/man5/${PROJECT_TARGET}.5"
                   COMMAND ${CMAKE_COMMAND} -E remove "${CMAKE_INSTALL_PREFIX}/${PROJECT_MAN_PATH}/man8/${PROJECT_TARGET}.8"
                   COMMAND "execute_process( COMMAND mandb )"
                   COMMENT "Uninstalling the project ..." )

################################################################################################################################################################
# End of 'CMakeLists.txt'
################################################################################################################################################################
