using System.Runtime.InteropServices;
using System.Security.Principal;

namespace LocalDocumentOrganizer.Infrastructure.Windows.Documents;

public sealed class AppContainerProfile : IDisposable
{
    public const string ProfileName =
        "ProofToClosure.DocumentExtractionWorker.v1";

    private SafeSidHandle? _sid;

    private AppContainerProfile(SafeSidHandle sid, string sidValue, string folderPath)
    {
        _sid = sid;
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
        var result = WorkerNativeMethods.CreateAppContainerProfile(
            ProfileName,
            "ProofToClosure Document Extraction Worker",
            "Capability-free document extraction worker",
            IntPtr.Zero,
            0,
            out var sidPointer);

        if (result == WorkerNativeMethods.ErrorAlreadyExists)
        {
            result = WorkerNativeMethods.DeriveAppContainerSidFromAppContainerName(
                ProfileName,
                out sidPointer);
        }

        if (result < 0 || sidPointer == IntPtr.Zero)
        {
            throw AppContainerLaunchException.FromHResult(
                "AppContainer profile creation",
                result);
        }

        var sid = new SafeSidHandle(sidPointer);
        try
        {
            var sidValue = new SecurityIdentifier(sidPointer).Value;
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

            return new AppContainerProfile(sid, sidValue, folderPath);
        }
        catch
        {
            sid.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _sid, null)?.Dispose();
    }
}
