# Kernel Injector Driver

## Introduction

The Kernel Injector Driver is a kernel-mode component designed to facilitate injection of code or data into user-mode processes from the kernel space. This driver communicates with the Usermode Interface, via IOCTL (Input/Output Control) to perform injection tasks. As of the current version, the handle hijacking feature is not yet implemented and the mapping process will be added in future updates.

## Features

- Injection of code or data into user-mode processes.
- Communication with user-mode applications through IOCTL.
- Planned handle hijacking

## Requirements

- Compatible operating system (Windows).
- Kernel-mode development environment (such as Visual Studio with WDK).

## Usage

Windows must be in test mode to start the driver by bcdedit /set testsigning on and you have to deactivate your antivirus

Launch the user-mode application [https://github.com/heap-gh/KrnlInjector_Umode] after installing an running the driver

## Implementation Details

- IOCTL Communication: IOCTL codes to handle requests from user-mode application.
- Injection Methods: Manual Mapping
- Handle Hijacking (Future)

## Installation

After compiling the binaries

1. sc create (service name) binPath= (path to your .sys file) type= kernel
2. sc start (service name)

## Configuration

No specific configuration is required for the Driver

