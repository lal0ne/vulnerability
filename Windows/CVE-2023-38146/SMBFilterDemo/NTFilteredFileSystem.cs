/* Copyright (C) 2017-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using SMBLibrary;
using SMBLibrary.Win32;
using Utilities;

namespace SMBFilterDemo
{

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr Buffer;

        public UNICODE_STRING(string value)
        {
            Length = (ushort)(value.Length * 2);
            MaximumLength = (ushort)(value.Length + 2);
            Buffer = Marshal.StringToHGlobalUni(value);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(Buffer);
            Buffer = IntPtr.Zero;
        }

        public override string ToString()
        {
            return Marshal.PtrToStringUni(Buffer);
        }
    }

    [StructLayoutAttribute(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayoutAttribute(LayoutKind.Sequential)]
    public struct IO_STATUS_BLOCK
    {
        public UInt32 Status;
        public IntPtr Information;
    }

    internal class PendingRequest
    {
        public IntPtr FileHandle;
        public uint ThreadID;
        public IO_STATUS_BLOCK IOStatusBlock;
        public bool Cleanup;
    }

    internal class PendingRequestCollection
    {
        private Dictionary<IntPtr, List<PendingRequest>> m_handleToNotifyChangeRequests = new Dictionary<IntPtr, List<PendingRequest>>();

        public void Add(PendingRequest request)
        {
            lock (m_handleToNotifyChangeRequests)
            {
                List<PendingRequest> pendingRequests;
                bool containsKey = m_handleToNotifyChangeRequests.TryGetValue(request.FileHandle, out pendingRequests);
                if (containsKey)
                {
                    pendingRequests.Add(request);
                }
                else
                {
                    pendingRequests = new List<PendingRequest>();
                    pendingRequests.Add(request);
                    m_handleToNotifyChangeRequests.Add(request.FileHandle, pendingRequests);
                }
            }
        }

        public void Remove(IntPtr handle, uint threadID)
        {
            lock (m_handleToNotifyChangeRequests)
            {
                List<PendingRequest> pendingRequests;
                bool containsKey = m_handleToNotifyChangeRequests.TryGetValue(handle, out pendingRequests);
                if (containsKey)
                {
                    for (int index = 0; index < pendingRequests.Count; index++)
                    {
                        if (pendingRequests[index].ThreadID == threadID)
                        {
                            pendingRequests.RemoveAt(index);
                            index--;
                        }
                    }

                    if (pendingRequests.Count == 0)
                    {
                        m_handleToNotifyChangeRequests.Remove(handle);
                    }
                }
            }
        }

        public List<PendingRequest> GetRequestsByHandle(IntPtr handle)
        {
            List<PendingRequest> pendingRequests;
            bool containsKey = m_handleToNotifyChangeRequests.TryGetValue((IntPtr)handle, out pendingRequests);
            if (containsKey)
            {
                return new List<PendingRequest>(pendingRequests);
            }
            return new List<PendingRequest>();
        }
    }

    public class CreateFileInfo
    {
        public string Path;
        public AccessMask DesiredAccess;
        public SMBLibrary.FileAttributes FileAttributes;
        public ShareAccess ShareAccess;
        public CreateDisposition CreateDisposition;
        public CreateOptions CreateOptions;
        public NTStatus Status;
        public bool ReturnImmediately;

        public CreateFileInfo(string path, AccessMask desiredAccess, SMBLibrary.FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions)
        {
            Path = path;
            DesiredAccess = desiredAccess;
            FileAttributes = fileAttributes;
            ShareAccess = shareAccess;
            CreateDisposition = createDisposition;
            CreateOptions = createOptions;
            Status = NTStatus.STATUS_SUCCESS;
            ReturnImmediately = false;
        }

        public void Return(NTStatus status)
        {
            Status = status;
            ReturnImmediately = true;
        }
    }


    public class NTFilteredFileSystem : INTFileStore
    {
        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        private static extern NTStatus NtCreateFile(out IntPtr handle, uint desiredAccess, ref OBJECT_ATTRIBUTES objectAttributes, out IO_STATUS_BLOCK ioStatusBlock, ref long allocationSize, SMBLibrary.FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, IntPtr eaBuffer, uint eaLength);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        private static extern NTStatus NtClose(IntPtr handle);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        private static extern NTStatus NtReadFile(IntPtr handle, IntPtr evt, IntPtr apcRoutine, IntPtr apcContext, out IO_STATUS_BLOCK ioStatusBlock, byte[] buffer, uint length, ref long byteOffset, IntPtr key);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        private static extern NTStatus NtWriteFile(IntPtr handle, IntPtr evt, IntPtr apcRoutine, IntPtr apcContext, out IO_STATUS_BLOCK ioStatusBlock, byte[] buffer, uint length, ref long byteOffset, IntPtr key);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        private static extern NTStatus NtFlushBuffersFile(IntPtr handle, out IO_STATUS_BLOCK ioStatusBlock);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        private static extern NTStatus NtLockFile(IntPtr handle, IntPtr evt, IntPtr apcRoutine, IntPtr apcContext, out IO_STATUS_BLOCK ioStatusBlock, ref long byteOffset, ref long length, uint key, bool failImmediately, bool exclusiveLock);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        private static extern NTStatus NtUnlockFile(IntPtr handle, out IO_STATUS_BLOCK ioStatusBlock, ref long byteOffset, ref long length, uint key);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        private static extern NTStatus NtQueryDirectoryFile(IntPtr handle, IntPtr evt, IntPtr apcRoutine, IntPtr apcContext, out IO_STATUS_BLOCK ioStatusBlock, byte[] fileInformation, uint length, uint fileInformationClass, bool returnSingleEntry, ref UNICODE_STRING fileName, bool restartScan);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        private static extern NTStatus NtQueryInformationFile(IntPtr handle, out IO_STATUS_BLOCK ioStatusBlock, byte[] fileInformation, uint length, uint fileInformationClass);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        private static extern NTStatus NtSetInformationFile(IntPtr handle, out IO_STATUS_BLOCK ioStatusBlock, byte[] fileInformation, uint length, uint fileInformationClass);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        private static extern NTStatus NtQueryVolumeInformationFile(IntPtr handle, out IO_STATUS_BLOCK ioStatusBlock, byte[] fsInformation, uint length, uint fsInformationClass);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        private static extern NTStatus NtSetVolumeInformationFile(IntPtr handle, out IO_STATUS_BLOCK ioStatusBlock, byte[] fsInformation, uint length, uint fsInformationClass);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        private static extern NTStatus NtQuerySecurityObject(IntPtr handle, SecurityInformation securityInformation, byte[] securityDescriptor, uint length, out uint lengthNeeded);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        private static extern NTStatus NtSetSecurityObject(IntPtr handle, SecurityInformation securityInformation, byte[] securityDescriptor);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        private static extern NTStatus NtNotifyChangeDirectoryFile(IntPtr handle, IntPtr evt, IntPtr apcRoutine, IntPtr apcContext, out IO_STATUS_BLOCK ioStatusBlock, byte[] buffer, uint bufferSize, NotifyChangeFilter completionFilter, bool watchTree);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        private static extern NTStatus NtFsControlFile(IntPtr handle, IntPtr evt, IntPtr apcRoutine, IntPtr apcContext, out IO_STATUS_BLOCK ioStatusBlock, uint ioControlCode, byte[] inputBuffer, uint inputBufferLength, byte[] outputBuffer, uint outputBufferLength);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        private static extern NTStatus NtAlertThread(IntPtr threadHandle);

        // Available starting from Windows Vista.
        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        private static extern NTStatus NtCancelSynchronousIoFile(IntPtr threadHandle, IntPtr ioRequestToCancel, out IO_STATUS_BLOCK ioStatusBlock);

        private static readonly int QueryDirectoryBufferSize = 4096;
        private static readonly int FileInformationBufferSize = 8192;
        private static readonly int FileSystemInformationBufferSize = 4096;

        private DirectoryInfo m_directory;
        private PendingRequestCollection m_pendingRequests = new PendingRequestCollection();

        private Action<CreateFileInfo> m_createFileFilter = null;

        public NTFilteredFileSystem(string path) : this(new DirectoryInfo(path))
        {
        }

        public NTFilteredFileSystem(DirectoryInfo directory)
        {
            m_directory = directory;
        }

        private OBJECT_ATTRIBUTES InitializeObjectAttributes(UNICODE_STRING objectName)
        {
            OBJECT_ATTRIBUTES objectAttributes = new OBJECT_ATTRIBUTES();
            objectAttributes.RootDirectory = IntPtr.Zero;
            objectAttributes.ObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(objectName));
            Marshal.StructureToPtr(objectName, objectAttributes.ObjectName, false);
            objectAttributes.SecurityDescriptor = IntPtr.Zero;
            objectAttributes.SecurityQualityOfService = IntPtr.Zero;

            objectAttributes.Length = Marshal.SizeOf(objectAttributes);
            return objectAttributes;
        }

        public void SetCreateFileFilter(Action<CreateFileInfo> createFileFilter)
        {
            m_createFileFilter = createFileFilter;
        }

        private NTStatus CreateFile(out IntPtr handle, out FileStatus fileStatus, string nativePath, AccessMask desiredAccess, long allocationSize, SMBLibrary.FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions)
        {
            CreateFileInfo createFileInfo = new CreateFileInfo(nativePath, desiredAccess, fileAttributes, shareAccess, createDisposition, createOptions);
            if (m_createFileFilter != null)
            {
                m_createFileFilter(createFileInfo);
                if (createFileInfo.ReturnImmediately)
                {
                    handle = (IntPtr)0xFFFFFFFF;
                    fileStatus = 0;
                    return createFileInfo.Status;
                }
            }
            UNICODE_STRING objectName = new UNICODE_STRING(createFileInfo.Path);
            OBJECT_ATTRIBUTES objectAttributes = InitializeObjectAttributes(objectName);
            IO_STATUS_BLOCK ioStatusBlock;
            NTStatus status = NtCreateFile(out handle, (uint)createFileInfo.DesiredAccess, ref objectAttributes, out ioStatusBlock, ref allocationSize, createFileInfo.FileAttributes, createFileInfo.ShareAccess, createFileInfo.CreateDisposition, createFileInfo.CreateOptions, IntPtr.Zero, 0);
            fileStatus = (FileStatus)ioStatusBlock.Information;
            return status;
        }

        private string ToNativePath(string path)
        {
            if (!path.StartsWith(@"\"))
            {
                path = @"\" + path;
            }
            return @"\??\" + m_directory.FullName + path;
        }

        public NTStatus CreateFile(out object handle, out FileStatus fileStatus, string path, AccessMask desiredAccess, SMBLibrary.FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext)
        {
            IntPtr fileHandle;
            string nativePath = ToNativePath(path);
            // NtQueryDirectoryFile will return STATUS_PENDING if the directory handle was not opened with SYNCHRONIZE and FILE_SYNCHRONOUS_IO_ALERT or FILE_SYNCHRONOUS_IO_NONALERT.
            // Our usage of NtNotifyChangeDirectoryFile assumes the directory handle is opened with SYNCHRONIZE and FILE_SYNCHRONOUS_IO_ALERT (or FILE_SYNCHRONOUS_IO_NONALERT starting from Windows Vista).
            // Note: Sometimes a directory will be opened without specifying FILE_DIRECTORY_FILE.
            desiredAccess |= AccessMask.SYNCHRONIZE;
            createOptions &= ~CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT;
            createOptions |= CreateOptions.FILE_SYNCHRONOUS_IO_ALERT;

            if ((createOptions & CreateOptions.FILE_NO_INTERMEDIATE_BUFFERING) > 0 &&
                ((FileAccessMask)desiredAccess & FileAccessMask.FILE_APPEND_DATA) > 0)
            {
                // FILE_NO_INTERMEDIATE_BUFFERING is incompatible with FILE_APPEND_DATA
                // [MS-SMB2] 3.3.5.9 suggests setting FILE_APPEND_DATA to zero in this case.
                desiredAccess = (AccessMask)((uint)desiredAccess & (uint)~FileAccessMask.FILE_APPEND_DATA);
            }

            NTStatus status = CreateFile(out fileHandle, out fileStatus, nativePath, desiredAccess, 0, fileAttributes, shareAccess, createDisposition, createOptions);
            handle = fileHandle;
            return status;
        }

        public NTStatus CloseFile(object handle)
        {
            // [MS-FSA] 2.1.5.4 The close operation has to complete any pending ChangeNotify request with STATUS_NOTIFY_CLEANUP.
            // - When closing a synchronous handle we must explicitly cancel any pending ChangeNotify request, otherwise the call to NtClose will hang.
            //   We use request.Cleanup to tell that we should complete such ChangeNotify request with STATUS_NOTIFY_CLEANUP.
            // - When closing an asynchronous handle Windows will implicitly complete any pending ChangeNotify request with STATUS_NOTIFY_CLEANUP as required.
            List<PendingRequest> pendingRequests = m_pendingRequests.GetRequestsByHandle((IntPtr)handle);
            foreach (PendingRequest request in pendingRequests)
            {
                request.Cleanup = true;
                Cancel(request);
            }
            return NtClose((IntPtr)handle);
        }

        public NTStatus ReadFile(out byte[] data, object handle, long offset, int maxCount)
        {
            IO_STATUS_BLOCK ioStatusBlock;
            data = new byte[maxCount];
            NTStatus status = NtReadFile((IntPtr)handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ioStatusBlock, data, (uint)maxCount, ref offset, IntPtr.Zero);
            if (status == NTStatus.STATUS_SUCCESS)
            {
                int bytesRead = (int)ioStatusBlock.Information;
                if (bytesRead < maxCount)
                {
                    data = ByteReader.ReadBytes(data, 0, bytesRead);
                }
            }
            return status;
        }

        public NTStatus WriteFile(out int numberOfBytesWritten, object handle, long offset, byte[] data)
        {
            IO_STATUS_BLOCK ioStatusBlock;
            NTStatus status = NtWriteFile((IntPtr)handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ioStatusBlock, data, (uint)data.Length, ref offset, IntPtr.Zero);
            if (status == NTStatus.STATUS_SUCCESS)
            {
                numberOfBytesWritten = (int)ioStatusBlock.Information;
            }
            else
            {
                numberOfBytesWritten = 0;
            }
            return status;
        }

        public NTStatus FlushFileBuffers(object handle)
        {
            IO_STATUS_BLOCK ioStatusBlock;
            return NtFlushBuffersFile((IntPtr)handle, out ioStatusBlock);
        }

        public NTStatus LockFile(object handle, long byteOffset, long length, bool exclusiveLock)
        {
            IO_STATUS_BLOCK ioStatusBlock;
            return NtLockFile((IntPtr)handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ioStatusBlock, ref byteOffset, ref length, 0, true, exclusiveLock);
        }

        public NTStatus UnlockFile(object handle, long byteOffset, long length)
        {
            IO_STATUS_BLOCK ioStatusBlock;
            return NtUnlockFile((IntPtr)handle, out ioStatusBlock, ref byteOffset, ref length, 0);
        }

        public NTStatus QueryDirectory(out List<QueryDirectoryFileInformation> result, object handle, string fileName, FileInformationClass informationClass)
        {
            IO_STATUS_BLOCK ioStatusBlock;
            byte[] buffer = new byte[QueryDirectoryBufferSize];
            UNICODE_STRING fileNameStructure = new UNICODE_STRING(fileName);
            result = new List<QueryDirectoryFileInformation>();
            bool restartScan = true;
            while (true)
            {
                NTStatus status = NtQueryDirectoryFile((IntPtr)handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ioStatusBlock, buffer, (uint)buffer.Length, (byte)informationClass, false, ref fileNameStructure, restartScan);
                if (status == NTStatus.STATUS_NO_MORE_FILES)
                {
                    break;
                }
                else if (status != NTStatus.STATUS_SUCCESS)
                {
                    return status;
                }
                int numberOfBytesWritten = (int)ioStatusBlock.Information;
                List<QueryDirectoryFileInformation> page = QueryDirectoryFileInformation.ReadFileInformationList(buffer, 0, informationClass);
                result.AddRange(page);
                restartScan = false;
            }
            fileNameStructure.Dispose();
            return NTStatus.STATUS_SUCCESS;
        }

        public NTStatus GetFileInformation(out FileInformation result, object handle, FileInformationClass informationClass)
        {
            IO_STATUS_BLOCK ioStatusBlock;
            byte[] buffer = new byte[FileInformationBufferSize];
            NTStatus status = NtQueryInformationFile((IntPtr)handle, out ioStatusBlock, buffer, (uint)buffer.Length, (uint)informationClass);
            if (status == NTStatus.STATUS_SUCCESS)
            {
                int numberOfBytesWritten = (int)ioStatusBlock.Information;
                buffer = ByteReader.ReadBytes(buffer, 0, numberOfBytesWritten);
                result = FileInformation.GetFileInformation(buffer, 0, informationClass);
            }
            else
            {
                result = null;
            }
            return status;
        }

        public NTStatus SetFileInformation(object handle, FileInformation information)
        {
            IO_STATUS_BLOCK ioStatusBlock;
            if (information is FileRenameInformationType2)
            {
                FileRenameInformationType2 fileRenameInformationRemote = (FileRenameInformationType2)information;
                if (ProcessHelper.Is64BitProcess)
                {
                    // We should not modify the FileRenameInformationType2 instance we received - the caller may use it later.
                    FileRenameInformationType2 fileRenameInformationLocal = new FileRenameInformationType2();
                    fileRenameInformationLocal.ReplaceIfExists = fileRenameInformationRemote.ReplaceIfExists;
                    fileRenameInformationLocal.FileName = ToNativePath(fileRenameInformationRemote.FileName);
                    information = fileRenameInformationLocal;
                }
                else
                {
                    // Note: WOW64 process should use FILE_RENAME_INFORMATION_TYPE_1.
                    // Note: Server 2003 x64 has issues with using FILE_RENAME_INFORMATION under WOW64.
                    FileRenameInformationType1 fileRenameInformationLocal = new FileRenameInformationType1();
                    fileRenameInformationLocal.ReplaceIfExists = fileRenameInformationRemote.ReplaceIfExists;
                    fileRenameInformationLocal.FileName = ToNativePath(fileRenameInformationRemote.FileName);
                    information = fileRenameInformationLocal;
                }
            }
            else if (information is FileLinkInformationType2)
            {
                FileLinkInformationType2 fileLinkInformationRemote = (FileLinkInformationType2)information;
                if (ProcessHelper.Is64BitProcess)
                {
                    FileRenameInformationType2 fileLinkInformationLocal = new FileRenameInformationType2();
                    fileLinkInformationLocal.ReplaceIfExists = fileLinkInformationRemote.ReplaceIfExists;
                    fileLinkInformationLocal.FileName = ToNativePath(fileLinkInformationRemote.FileName);
                    information = fileLinkInformationRemote;
                }
                else
                {
                    FileLinkInformationType1 fileLinkInformationLocal = new FileLinkInformationType1();
                    fileLinkInformationLocal.ReplaceIfExists = fileLinkInformationRemote.ReplaceIfExists;
                    fileLinkInformationLocal.FileName = ToNativePath(fileLinkInformationRemote.FileName);
                    information = fileLinkInformationRemote;
                }
            }
            byte[] buffer = information.GetBytes();
            return NtSetInformationFile((IntPtr)handle, out ioStatusBlock, buffer, (uint)buffer.Length, (uint)information.FileInformationClass);
        }

        public NTStatus GetFileSystemInformation(out FileSystemInformation result, FileSystemInformationClass informationClass)
        {
            IO_STATUS_BLOCK ioStatusBlock;
            byte[] buffer = new byte[FileSystemInformationBufferSize];
            IntPtr volumeHandle;
            FileStatus fileStatus;
            string nativePath = @"\??\" + m_directory.FullName.Substring(0, 3);
            NTStatus status = CreateFile(out volumeHandle, out fileStatus, nativePath, AccessMask.GENERIC_READ, 0, (SMBLibrary.FileAttributes)0, ShareAccess.Read, CreateDisposition.FILE_OPEN, (CreateOptions)0);
            result = null;
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return status;
            }
            status = NtQueryVolumeInformationFile((IntPtr)volumeHandle, out ioStatusBlock, buffer, (uint)buffer.Length, (uint)informationClass);
            CloseFile(volumeHandle);
            if (status == NTStatus.STATUS_SUCCESS)
            {
                int numberOfBytesWritten = (int)ioStatusBlock.Information;
                buffer = ByteReader.ReadBytes(buffer, 0, numberOfBytesWritten);
                result = FileSystemInformation.GetFileSystemInformation(buffer, 0, informationClass);
            }
            return status;
        }

        public NTStatus SetFileSystemInformation(FileSystemInformation information)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus GetSecurityInformation(out SecurityDescriptor result, object handle, SecurityInformation securityInformation)
        {
            result = null;
            return NTStatus.STATUS_INVALID_DEVICE_REQUEST;
        }

        public NTStatus SetSecurityInformation(object handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor)
        {
            // [MS-FSA] If the object store does not implement security, the operation MUST be failed with STATUS_INVALID_DEVICE_REQUEST.
            return NTStatus.STATUS_INVALID_DEVICE_REQUEST;
        }

        public NTStatus NotifyChange(out object ioRequest, object handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context)
        {
            byte[] buffer = new byte[outputBufferSize];
            ManualResetEvent requestAddedEvent = new ManualResetEvent(false);
            PendingRequest request = new PendingRequest();
            Thread m_thread = new Thread(delegate ()
            {
                request.FileHandle = (IntPtr)handle;
                request.ThreadID = ThreadingHelper.GetCurrentThreadId();
                m_pendingRequests.Add(request);
                // The request has been added, we can now return STATUS_PENDING.
                requestAddedEvent.Set();
                // There is a possibility of race condition if the caller will wait for STATUS_PENDING and then immediate call Cancel, but this scenario is very unlikely.
                NTStatus status = NtNotifyChangeDirectoryFile((IntPtr)handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out request.IOStatusBlock, buffer, (uint)buffer.Length, completionFilter, watchTree);
                if (status == NTStatus.STATUS_SUCCESS)
                {
                    int length = (int)request.IOStatusBlock.Information;
                    buffer = ByteReader.ReadBytes(buffer, 0, length);
                }
                else
                {
                    const NTStatus STATUS_ALERTED = (NTStatus)0x00000101;
                    const NTStatus STATUS_OBJECT_TYPE_MISMATCH = (NTStatus)0xC0000024;

                    buffer = new byte[0];
                    if (status == STATUS_OBJECT_TYPE_MISMATCH)
                    {
                        status = NTStatus.STATUS_INVALID_HANDLE;
                    }
                    else if (status == STATUS_ALERTED)
                    {
                        status = NTStatus.STATUS_CANCELLED;
                    }

                    // If the handle is closing and we had to cancel a ChangeNotify request as part of a cleanup,
                    // we return STATUS_NOTIFY_CLEANUP as specified in [MS-FSA] 2.1.5.4.
                    if (status == NTStatus.STATUS_CANCELLED && request.Cleanup)
                    {
                        status = NTStatus.STATUS_NOTIFY_CLEANUP;
                    }
                }
                onNotifyChangeCompleted(status, buffer, context);
                m_pendingRequests.Remove((IntPtr)handle, request.ThreadID);
            });
            m_thread.Start();

            // We must wait for the request to be added in order for Cancel to function properly.
            requestAddedEvent.WaitOne();
            ioRequest = request;
            return NTStatus.STATUS_PENDING;
        }

        public NTStatus Cancel(object ioRequest)
        {
            PendingRequest request = (PendingRequest)ioRequest;
            const uint THREAD_TERMINATE = 0x00000001;
            const uint THREAD_ALERT = 0x00000004;
            uint threadID = request.ThreadID;
            IntPtr threadHandle = ThreadingHelper.OpenThread(THREAD_TERMINATE | THREAD_ALERT, false, threadID);
            if (threadHandle == IntPtr.Zero)
            {
                Win32Error error = (Win32Error)Marshal.GetLastWin32Error();
                if (error == Win32Error.ERROR_INVALID_PARAMETER)
                {
                    return NTStatus.STATUS_INVALID_HANDLE;
                }
                else
                {
                    throw new Exception("OpenThread failed, Win32 error: " + error.ToString("D"));
                }
            }

            NTStatus status;
            if (Environment.OSVersion.Version.Major >= 6)
            {
                IO_STATUS_BLOCK ioStatusBlock;
                status = NtCancelSynchronousIoFile(threadHandle, IntPtr.Zero, out ioStatusBlock);
            }
            else
            {
                // The handle was opened for synchronous operation so NtNotifyChangeDirectoryFile is blocking.
                // We MUST use NtAlertThread to send a signal to stop the wait. The handle cannot be closed otherwise.
                // Note: The handle was opened with CreateOptions.FILE_SYNCHRONOUS_IO_ALERT as required.
                status = NtAlertThread(threadHandle);
            }

            ThreadingHelper.CloseHandle(threadHandle);
            m_pendingRequests.Remove(request.FileHandle, request.ThreadID);
            return status;
        }

        public NTStatus DeviceIOControl(object handle, uint ctlCode, byte[] input, out byte[] output, int maxOutputLength)
        {
            switch ((IoControlCode)ctlCode)
            {
                case IoControlCode.FSCTL_IS_PATHNAME_VALID:
                case IoControlCode.FSCTL_GET_COMPRESSION:
                case IoControlCode.FSCTL_GET_RETRIEVAL_POINTERS:
                case IoControlCode.FSCTL_SET_OBJECT_ID:
                case IoControlCode.FSCTL_GET_OBJECT_ID:
                case IoControlCode.FSCTL_DELETE_OBJECT_ID:
                case IoControlCode.FSCTL_SET_OBJECT_ID_EXTENDED:
                case IoControlCode.FSCTL_CREATE_OR_GET_OBJECT_ID:
                case IoControlCode.FSCTL_SET_SPARSE:
                case IoControlCode.FSCTL_READ_FILE_USN_DATA:
                case IoControlCode.FSCTL_SET_DEFECT_MANAGEMENT:
                case IoControlCode.FSCTL_SET_COMPRESSION:
                case IoControlCode.FSCTL_QUERY_SPARING_INFO:
                case IoControlCode.FSCTL_QUERY_ON_DISK_VOLUME_INFO:
                case IoControlCode.FSCTL_SET_ZERO_ON_DEALLOCATION:
                case IoControlCode.FSCTL_QUERY_FILE_REGIONS:
                case IoControlCode.FSCTL_QUERY_ALLOCATED_RANGES:
                case IoControlCode.FSCTL_SET_ZERO_DATA:
                    {
                        IO_STATUS_BLOCK ioStatusBlock;
                        output = new byte[maxOutputLength];
                        NTStatus status = NtFsControlFile((IntPtr)handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ioStatusBlock, ctlCode, input, (uint)input.Length, output, (uint)maxOutputLength);
                        if (status == NTStatus.STATUS_SUCCESS)
                        {
                            int numberOfBytesWritten = (int)ioStatusBlock.Information;
                            output = ByteReader.ReadBytes(output, 0, numberOfBytesWritten);
                        }
                        return status;
                    }
                default:
                    {
                        output = null;
                        return NTStatus.STATUS_NOT_SUPPORTED;
                    }
            }
        }
    }
}
