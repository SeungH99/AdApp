using System.Collections.Immutable;

namespace LocalDocumentOrganizer.Core.Cases.Receivable;

/// <summary>Deterministic bundled ISO 4217 alpha-code catalog (ISO 4217:2024).</summary>
public static class Iso4217CurrencyCatalog
{
    public const string Version = "iso-4217-2024-bundled-v1";

    private const string Codes = """
        AED AFN ALL AMD AOA ARS AUD AWG AZN BAM BBD BDT BGN BHD BIF BMD BND BOB BOV BRL BSD BTN BWP BYN BZD CAD CDF CHE CHF CHW CLF CLP CNY COP COU CRC CUP CVE CZK DJF DKK DOP DZD EGP ERN ETB EUR FJD FKP GBP GEL GHS GIP GMD GNF GTQ GYD HKD HNL HRK HTG HUF IDR ILS INR IQD IRR ISK JMD JOD JPY KES KGS KHR KMF KPW KRW KWD KYD KZT LAK LBP LKR LRD LSL LYD MAD MDL MGA MKD MMK MNT MOP MRU MUR MVR MWK MXN MXV MYR MZN NAD NGN NIO NOK NPR NZD OMR PAB PEN PGK PHP PKR PLN PYG QAR RON RSD RUB RWF SAR SBD SCR SDG SEK SGD SHP SLE SLL SOS SRD SSP STN SVC SYP SZL THB TJS TMT TND TOP TRY TTD TWD TZS UAH UGX USD USN UYI UYU UYW UZS VED VES VND VUV WST XAF XAG XAU XBA XBB XBC XBD XCD XDR XOF XPD XPF XPT XSU XTS XUA XXX YER ZAR ZMW ZWL
        """;

    public static ImmutableHashSet<string> ActiveAlphaCodes { get; } =
        Codes.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .ToImmutableHashSet(StringComparer.Ordinal);

    public static bool IsValid(string? value) =>
        value is { Length: 3 } && ActiveAlphaCodes.Contains(value);
}
