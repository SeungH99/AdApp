using System.Runtime.InteropServices;
using System.Security.Principal;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Documents;

public sealed class AppContainerProfile : IDisposable
{
    public const string ProfileName =
        "ProofToClosure.DocumentExtractionWorker.v1";

    private SafeSidHandle? _sid;
    private FileStream? _lifecycleLock;
    private int _cleanupUnsafe;
    private int _disposed;

    private AppContainerProfile(
        SafeSidHandle sid,
        string sidValue,
        string folderPath,
        FileStream lifecycleLock)
    {
        _sid = sid;
        _lifecycleLock = lifecycleLock;
        Sid = sidValue;
        FolderPath = folderPath;
    }

    public string Sid { get; }

    public string FolderPath { get; }

    internal SafeSidHandle GetSidHandle() =>
        _sid is { IsClosed: false, IsInvalid: false } sid
            ? sid
            : throw new ObjectDisposedException(nameof(AppContainerProfile));

    public static AppContainerProfile OpenOrCreate()
    {
        var lifecycleLock = AcquireLifecycleLock();
        IntPtr sidPointer = IntPtr.Zero;
        SafeSidHandle? sid = null;
        var profileCreated = false;
        try
        {
            DeleteProfileOrThrow("Stale AppContainer profile cleanup");

            var result = WorkerNativeMethods.CreateAppContainerProfile(
                ProfileName,
                "ProofToClosure Document Extraction Worker",
                "Capability-free document extraction worker",
                IntPtr.Zero,
                0,
                out sidPointer);

            if (result < 0 || sidPointer == IntPtr.Zero)
            {
                throw AppContainerLaunchException.FromHResult(
                    result == WorkerNativeMethods.ErrorAlreadyExists
                        ? "Exclusive AppContainer profile creation"
                        : "AppContainer profile creation",
                    result);
            }

            profileCreated = true;
            sid = new SafeSidHandle(sidPointer);
            sidPointer = IntPtr.Zero;
            var sidValue = new SecurityIdentifier(
                sid.DangerousGetHandle()).Value;
            var folderResult = WorkerNativeMethods.GetAppContainerFolderPath(
                sidValue,
                out var folderPointer);
            if (folderResult < 0 || folderPointer == IntPtr.Zero)
            {
                throw AppContainerLaunchException.FromHResult(
                    "AppContainer folder lookup",
                    folderResult);
            }

            string folderPath;
            try
            {
                folderPath = Marshal.PtrToStringUni(folderPointer)
                    ?? throw new AppContainerLaunchException(
                        "AppContainer folder lookup returned no path.");
            }
            finally
            {
                Marshal.FreeCoTaskMem(folderPointer);
            }

            var profile = new AppContainerProfile(
                sid,
                sidValue,
                folderPath,
                lifecycleLock);
            sid = null;
            return profile;
        }
        catch
        {
            sid?.Dispose();
            if (sidPointer != IntPtr.Zero)
            {
                using var pendingSid = new SafeSidHandle(sidPointer);
            }

            try
            {
                if (profileCreated)
                {
                    DeleteProfileOrThrow(
                        "Failed AppContainer profile cleanup");
                }
            }
            finally
            {
                lifecycleLock.Dispose();
            }

            throw;
        }
    }

    public void Dispose()
    {
        DisposeCore(deleteProfile: Volatile.Read(ref _cleanupUnsafe) == 0);
    }

    internal void MarkCleanupUnsafe()
    {
        Volatile.Write(ref _cleanupUnsafe, 1);
    }

    internal void ReleaseWithoutProfileDeletion()
    {
        DisposeCore(deleteProfile: false);
    }

    private void DisposeCore(bool deleteProfile)
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        Interlocked.Exchange(ref _sid, null)?.Dispose();
        var lifecycleLock = Interlocked.Exchange(
            ref _lifecycleLock,
            null);
        try
        {
            if (deleteProfile)
            {
                DeleteProfileOrThrow("AppContainer profile cleanup");
            }
        }
        finally
        {
            lifecycleLock?.Dispose();
        }
    }

    private static FileStream AcquireLifecycleLock()
    {
        try
        {
            var lockDirectory = Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.LocalApplicationData),
                "ProofToClosure",
                "Locks");
            Directory.CreateDirectory(lockDirectory);
            return new FileStream(
                Path.Combine(
                    lockDirectory,
                    "document-extraction-worker-profile.lock"),
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            throw new AppContainerLaunchException(
                "The AppContainer profile is already in use.");
        }
    }

    private static void DeleteProfileOrThrow(string operation)
    {
        var result = WorkerNativeMethods.DeleteAppContainerProfile(
            ProfileName);
        if (result < 0)
        {
            result = WorkerNativeMethods.DeleteAppContainerProfile(
                ProfileName);
        }

        if (result < 0)
        {
            throw AppContainerLaunchException.FromHResult(
                operation,
                result);
        }
    }
}
