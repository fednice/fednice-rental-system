// FEDNICE - House Parser - Handles A1-A10 and 1-20
export function parseHouses(houses) {
  return houses.map(h => {
    const houseNo = String(h.HouseNo).trim();
    const isASeries = houseNo.toUpperCase().startsWith('A');
    const numericPart = parseInt(houseNo.replace(/[^0-9]/g, ''), 10);
    return {
      ...h,
      houseNo,
      isASeries,
      numericPart,
      sortKey: isASeries ? 1000 + numericPart : numericPart,
      monthlyRent: Number(h.MonthlyRent) || 0
    };
  }).sort((a,b) => a.sortKey - b.sortKey);
}

export function getTotals(parsedHouses) {
  const totalHouses = parsedHouses.length;
  const occupied = parsedHouses.filter(h => h.Status === 'Occupied').length;
  const vacant = totalHouses - occupied;
  const expectedRent = parsedHouses.reduce((sum, h) => sum + h.monthlyRent, 0);
  return { totalHouses, occupied, vacant, expectedRent };
}