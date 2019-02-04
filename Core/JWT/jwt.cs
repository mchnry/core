namespace Mchnry.Core.JWT
{
    public struct jwt<H, T>
    {
        public H Header { get; set; }
        public T Token { get; set; }
    }
}
