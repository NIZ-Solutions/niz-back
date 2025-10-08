/*
  Warnings:

  - You are about to drop the column `advicedDate` on the `Payment` table. All the data in the column will be lost.
  - You are about to drop the column `advicedTime` on the `Payment` table. All the data in the column will be lost.
  - You are about to drop the column `method` on the `Payment` table. All the data in the column will be lost.
  - Added the required column `advicedAt` to the `Payment` table without a default value. This is not possible if the table is not empty.
  - Made the column `userId` on table `Payment` required. This step will fail if there are existing NULL values in that column.

*/
-- DropForeignKey
ALTER TABLE "public"."Payment" DROP CONSTRAINT "Payment_userId_fkey";

-- AlterTable
ALTER TABLE "public"."Payment" DROP COLUMN "advicedDate",
DROP COLUMN "advicedTime",
DROP COLUMN "method",
ADD COLUMN     "advicedAt" TIMESTAMP(3) NOT NULL,
ALTER COLUMN "userId" SET NOT NULL;

-- AddForeignKey
ALTER TABLE "public"."Payment" ADD CONSTRAINT "Payment_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
