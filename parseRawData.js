import changeCase from 'change-case';
import { XmlEntities } from 'html-entities';

const DELIMITER = ':';

const stripHTMLEntitites = (rawData) => {
    const entities = new XmlEntities();
    return entities.decode(rawData);
};

const getCommonDelimiterForm = (rawData, delimiter) => {
    const delimiterPattern = new RegExp(delimiter + '\\S+', 'g');
    const delimiterWSpacePattern = new RegExp(delimiter + ' ', 'g');
    const delimiterMatches = rawData.match(delimiterPattern) || [];
    const delimiterWSpaceMatches = rawData.match(delimiterWSpacePattern) || [];

    if (delimiterMatches.length > delimiterWSpaceMatches.length) {
        return delimiter;
    }
    return delimiter + ' ';
};

const parseRawData = (rawData) => {
    const result = {};
    rawData = stripHTMLEntitites(rawData);
    rawData = rawData.replace(/:\s*\r\n/g, ': ');
    const lines = rawData.split('\n');
    const delimiter = getCommonDelimiterForm(rawData, DELIMITER);

    lines.forEach((line) => {
        line = line.trim();

        if (line && line.includes(delimiter)) {
            const lineParts = line.split(DELIMITER);

            if (lineParts.length >= 2) {
                const key = changeCase.camelCase(lineParts[0]);
                const value = lineParts.splice(1).join(DELIMITER).trim();

                if (key in result) {
                    result[key] = `${result[key]} ${value}`;
                    return;
                }
                result[key] = value;
            }
        }
    });

    return result;
};

export default parseRawData;