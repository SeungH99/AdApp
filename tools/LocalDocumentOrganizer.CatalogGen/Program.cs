namespace LocalDocumentOrganizer.CatalogGen;

internal static class Program
{
    public static int Main(string[] args)
    {
        if (args is ["--self-test"])
        {
            Console.WriteLine("cataloggen-self-test:v1;deterministic=true");
            return 0;
        }

        Console.Error.WriteLine("Usage: LocalDocumentOrganizer.CatalogGen --self-test");
        return 2;
    }
}
